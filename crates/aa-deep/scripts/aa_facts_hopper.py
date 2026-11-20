# Reads facts out of the document Hopper has analyzed and writes them as JSON. Run by
# Analyze Anything (`--deep`) once Hopper's analysis has ended:
#
#   hopper -l <loader> -e <file> -Y <this script>
#
# Hopper's launcher takes no arguments for a script, so Analyze Anything writes two lines in
# front of this text that set REQUEST and ANSWER, the paths of the request and of the answer.
# The request names the functions and the strings to look for; the answer says which procedures
# use each, with addresses. The document is closed afterwards without being saved.

import json
import os
import re

MAX_USERS = 200
DECORATION = re.compile(r"^(imp___[A-Za-z_]*?__|__imp_|_OBJC_CLASS_\$_|j_)")


def plain(name):
    """A name as the request writes it: without what a linker, a loader or Hopper adds."""
    out = DECORATION.sub("", name)
    return out[1:] if out.startswith("_") else out


def procedure_at(document, address):
    segment = document.getSegmentAtAddress(address)
    if segment is None:
        return None, None
    return segment, segment.getProcedureAtAddress(address)


def is_stub(segment, entry):
    """True for the little procedures that only jump to an import."""
    section = segment.getSectionAtAddress(entry)
    return section is not None and "stub" in (section.getName() or "").lower()


def users_of(document, targets, themselves):
    users = {}
    for target in targets:
        segment = document.getSegmentAtAddress(target)
        if segment is None:
            continue
        for source in segment.getReferencesOfAddress(target) or []:
            home, procedure = procedure_at(document, source)
            if procedure is None:
                continue
            entry = procedure.getEntryPoint()
            if entry in themselves or is_stub(home, entry) or entry in users:
                continue
            users[entry] = source
    listed = []
    for entry, source in sorted(users.items())[:MAX_USERS]:
        item = {"function": document.getNameAtAddress(entry) or ("sub_%x" % entry), "address": entry, "at": source}
        offset = document.getFileOffsetFromAddress(source)
        if offset is not None and offset >= 0:
            item["offset"] = offset
        listed.append(item)
    return {"total": len(users), "users": listed}


def gather(document, request):
    wanted = dict((name, set()) for name in request["apis"])
    procedures = 0
    strings = dict((value, set()) for value in request["strings"])
    for segment in document.getSegmentsList():
        for index in range(segment.getProcedureCount()):
            entry = segment.getProcedureAtIndex(index).getEntryPoint()
            if not is_stub(segment, entry):
                procedures += 1
        for address in segment.getNamedAddresses() or []:
            found = wanted.get(plain(segment.getNameAtAddress(address) or ""))
            if found is not None:
                found.add(address)
        if strings:
            for index in range(segment.getStringCount()):
                text = segment.getStringAtIndex(index) or ""
                for value, places in strings.items():
                    if value in text:
                        places.add(segment.getStringAddressAtIndex(index))

    apis = []
    for name in request["apis"]:
        if wanted[name]:
            entry = {"name": name}
            entry.update(users_of(document, wanted[name], wanted[name]))
            apis.append(entry)

    found_strings = []
    for value in request["strings"]:
        places = strings[value]
        if not places:
            continue
        # A string object (Objective-C, Swift) points at the characters; code points at the
        # object, which starts a little before the pointer. Follow one such step.
        reached = set(places)
        for place in places:
            segment = document.getSegmentAtAddress(place)
            for source in (segment.getReferencesOfAddress(place) or []) if segment else []:
                if procedure_at(document, source)[1] is None:
                    reached.update([source, source - 8, source - 16])
        entry = {"value": value}
        entry.update(users_of(document, reached, set()))
        found_strings.append(entry)

    return {
        "tool": "hopper",
        "version": GlobalInformation.getHopperVersion(),
        "language": "64-bit" if document.is64Bits() else "32-bit",
        "functions": procedures,
        "apis": apis,
        "strings": found_strings,
    }


def main():
    document = Document.getCurrentDocument()
    try:
        with open(REQUEST) as handle:
            request = json.load(handle)
        # The script may be started while Hopper is still finding procedures.
        document.waitForBackgroundProcessToEnd()
        answer = gather(document, request)
    except Exception as error:  # the answer says what went wrong; Analyze Anything reports it
        answer = {"error": "%s: %s" % (type(error).__name__, error)}
    with open(ANSWER + ".part", "w") as handle:
        json.dump(answer, handle)
    os.rename(ANSWER + ".part", ANSWER)
    document.closeDocument()


main()
