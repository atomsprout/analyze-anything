// Reads facts out of the program Ghidra has analyzed and writes them as JSON. Run by
// Analyze Anything (`--deep`) as a headless post-script:
//
//   analyzeHeadless <project dir> <name> -import <file> -postScript AaFacts.java <request.json> <facts.json>
//
// The request names the functions and the strings to look for; the answer says which functions
// of the program use each, with addresses. Nothing in the program is changed, and nothing but
// the answer file is written.
//@category Analysis

import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.database.mem.AddressSourceInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class AaFacts extends GhidraScript {
    // Most users listed for one function or string; the count of all of them is given too.
    private static final int MAX_USERS = 200;

    private FunctionManager functions;

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 2) {
            throw new IllegalArgumentException("usage: AaFacts.java <request.json> <facts.json>");
        }
        JsonObject request;
        try (FileReader reader = new FileReader(arguments[0])) {
            request = JsonParser.parseReader(reader).getAsJsonObject();
        }
        functions = currentProgram.getFunctionManager();

        JsonObject facts = new JsonObject();
        facts.addProperty("tool", "ghidra");
        facts.addProperty("version", Application.getApplicationVersion());
        facts.addProperty("language", currentProgram.getLanguageID().toString());
        facts.addProperty("functions", countOwnFunctions());
        facts.add("apis", apis(request.getAsJsonArray("apis")));
        facts.add("strings", strings(request.getAsJsonArray("strings")));
        try (FileWriter writer = new FileWriter(arguments[1])) {
            new Gson().toJson(facts, writer);
        }
    }

    /** Functions with a body in this program: not the stubs that only jump to an import. */
    private int countOwnFunctions() {
        int count = 0;
        FunctionIterator all = functions.getFunctions(true);
        while (all.hasNext()) {
            if (!all.next().isThunk()) {
                count++;
            }
        }
        return count;
    }

    /** A name as the request writes it: without the decoration a linker or loader adds. */
    private static String plain(String name) {
        String out = name;
        for (String prefix : new String[] { "__imp_", "_OBJC_CLASS_$_", "_" }) {
            if (out.startsWith(prefix)) {
                out = out.substring(prefix.length());
            }
        }
        return out;
    }

    private JsonArray apis(JsonArray wanted) throws Exception {
        // Where each wanted function can be reached: itself, the stubs that jump to it, and the
        // symbols (pointers, class references) that carry its name.
        Map<String, Set<Address>> targets = new LinkedHashMap<>();
        for (JsonElement name : wanted) {
            targets.put(name.getAsString(), new LinkedHashSet<>());
        }
        List<Function> candidates = new ArrayList<>();
        functions.getFunctions(true).forEachRemaining(candidates::add);
        functions.getExternalFunctions().forEachRemaining(candidates::add);
        for (Function function : candidates) {
            Set<Address> found = targets.get(plain(function.getName()));
            if (found == null) {
                continue;
            }
            found.add(function.getEntryPoint());
            Address[] thunks = function.getFunctionThunkAddresses(true);
            if (thunks != null) {
                for (Address thunk : thunks) {
                    found.add(thunk);
                }
            }
        }
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            monitor.checkCancelled();
            Symbol symbol = symbols.next();
            Set<Address> found = targets.get(plain(symbol.getName()));
            if (found != null && symbol.getAddress().isMemoryAddress()) {
                found.add(symbol.getAddress());
            }
        }

        JsonArray out = new JsonArray();
        for (Map.Entry<String, Set<Address>> entry : targets.entrySet()) {
            if (entry.getValue().isEmpty()) {
                continue;
            }
            JsonObject api = new JsonObject();
            api.addProperty("name", entry.getKey());
            addUsers(api, entry.getValue(), entry.getValue());
            out.add(api);
        }
        return out;
    }

    private JsonArray strings(JsonArray wanted) throws Exception {
        JsonArray out = new JsonArray();
        if (wanted.isEmpty()) {
            return out;
        }
        Map<String, Set<Address>> places = new LinkedHashMap<>();
        for (JsonElement value : wanted) {
            places.put(value.getAsString(), new LinkedHashSet<>());
        }
        DataIterator defined = currentProgram.getListing().getDefinedData(true);
        while (defined.hasNext()) {
            monitor.checkCancelled();
            Data data = defined.next();
            if (!data.hasStringValue() || data.getValue() == null) {
                continue;
            }
            String text = data.getValue().toString();
            for (Map.Entry<String, Set<Address>> entry : places.entrySet()) {
                if (text.contains(entry.getKey())) {
                    entry.getValue().add(data.getAddress());
                }
            }
        }
        for (Map.Entry<String, Set<Address>> entry : places.entrySet()) {
            if (entry.getValue().isEmpty()) {
                continue;
            }
            // A string object (Objective-C, Swift, Go) points at the characters; code points at
            // the object. Follow one such step from data that is not inside a function.
            Set<Address> reached = new LinkedHashSet<>(entry.getValue());
            for (Address place : entry.getValue()) {
                ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(place);
                while (references.hasNext()) {
                    Address from = references.next().getFromAddress();
                    if (functions.getFunctionContaining(from) == null) {
                        Data holder = currentProgram.getListing().getDataContaining(from);
                        if (holder != null) {
                            reached.add(holder.getAddress());
                        }
                    }
                }
            }
            JsonObject string = new JsonObject();
            string.addProperty("value", entry.getKey());
            addUsers(string, reached, new LinkedHashSet<>());
            out.add(string);
        }
        return out;
    }

    /** Adds to `into` the functions that refer to any of `targets`, leaving out `themselves`. */
    private void addUsers(JsonObject into, Set<Address> targets, Set<Address> themselves) throws Exception {
        Map<Address, Address> users = new LinkedHashMap<>();
        for (Address target : targets) {
            ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(target);
            while (references.hasNext()) {
                monitor.checkCancelled();
                Reference reference = references.next();
                Function user = functions.getFunctionContaining(reference.getFromAddress());
                if (user == null || user.isThunk() || themselves.contains(user.getEntryPoint())) {
                    continue;
                }
                users.putIfAbsent(user.getEntryPoint(), reference.getFromAddress());
            }
        }
        JsonArray list = new JsonArray();
        for (Map.Entry<Address, Address> entry : users.entrySet()) {
            if (list.size() >= MAX_USERS) {
                break;
            }
            Function user = functions.getFunctionAt(entry.getKey());
            JsonObject item = new JsonObject();
            item.addProperty("function", user.getName());
            item.addProperty("address", entry.getKey().getOffset());
            item.addProperty("at", entry.getValue().getOffset());
            AddressSourceInfo source = currentProgram.getMemory().getAddressSourceInfo(entry.getValue());
            if (source != null && source.getFileOffset() >= 0) {
                item.addProperty("offset", source.getFileOffset());
            }
            list.add(item);
        }
        into.addProperty("total", users.size());
        into.add("users", list);
    }
}
