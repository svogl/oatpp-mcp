#!/usr/bin/env python3
"""
Mutation check for the security fixes in this module.

Revert one deliberate decision at a time, rebuild, and require the test suite to fail. A mutation
that nothing notices marks a decision the tests do not actually protect - which is a different
statement from "the tests pass", and the only one of the two that says anything about the future.

    python3 tools_mutation_check.py            # all mutations
    python3 tools_mutation_check.py --list     # what would be tried
    python3 tools_mutation_check.py --only 7   # one mutation, by number

Each entry is (description, file, text-to-revert, replacement). The pattern must match exactly once;
a pattern that matches nothing is reported as SKIPPED rather than silently passing, because a
mutation whose pattern did not survive a refactor is a hole in this file, not a clean run.

!! Do not `git commit` while this is running. It edits the working tree, and an `git add -A` in the
!! middle of it commits a mutation - which in `git show --stat` looks like nothing more than an
!! unrelated one-line change in an unrelated commit.
"""

import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(ROOT, "build")

LISTENER = "src/oatpp-mcp/Listener.cpp"
SESSION = "src/oatpp-mcp/event/Session.cpp"

# ---------------------------------------------------------------------------------------------
# F3 - remote denial of service on malformed messages
# ---------------------------------------------------------------------------------------------

PARSE_CATCH = """  } catch (const std::exception& e) {
    OATPP_LOGw("Listener", "[{}] undecodable message: {}", session.getId(), e.what())
    /* No id could be read, so the error goes out with a null id - JSON-RPC §5. */
    sendRpcError(session, nullptr, rpc_error::ParseError, "Parse error");
    return;
  }"""

PARAMS_CHECK = "  if(!paramsNode.isUndefined() && !paramsNode.isNull() && !paramsNode.isMap()) {"
ID_CHECK = "    if(!(idNode.isString() || idNode.isIntPrimitive() || idNode.isFloatPrimitive())) {"
METHOD_CHECK = "  if(!methodNode.isString()) {"
DISPATCH_TAIL = "  } else if(hasId) {"
NORMALISE = "  if(call->params == nullptr || call->params->isUndefined() || call->params->isNull()) {"

TOOLS_ARGUMENTS_CHECK = """  if(!isAbsentOrMap(callParams->arguments)) {
    sendInvalidParams(session, call, "tools/call", "'arguments' must be an object");
    return;
  }"""

TOOLS_REMAP = """  oatpp::Object<dto::ClientParamsToolsCall> callParams;
  try {
    callParams = m_remapper.remap<oatpp::Object<dto::ClientParamsToolsCall>>(call->params);
  } catch (const std::exception& e) {
    sendInvalidParams(session, call, "tools/call", e.what());
    return;
  }"""

LISTEN_GUARD = """    try {

      auto event = m_inStream->read(std::chrono::milliseconds(5000));
      if(event) {
        listener->onEvent(*this, event);
      } else if (m_pinger) {
        m_pinger->onPing(*this);
      }

    } catch (const std::exception& e) {
      OATPP_LOGe("[oatpp::mcp::Session::listen()]",
                 "Error - listener threw for session {}, continuing: {}", m_id, e.what())
    } catch (...) {
      OATPP_LOGe("[oatpp::mcp::Session::listen()]",
                 "Error - listener threw an unknown exception for session {}, continuing", m_id)
    }"""


def handler_remap(method, dto):
    """The wrapped parameter remap of one handler."""
    return f"""  try {{
    m_remapper.remap<oatpp::Object<dto::{dto}>>(call->params);
  }} catch (const std::exception& e) {{
    sendInvalidParams(session, call, "{method}", e.what());
    return;
  }}"""


MUTATIONS = [
    # (description, file, revert, replace, test)
    ("F3: parse error is not answered with -32700", LISTENER, PARSE_CATCH,
     "  } catch (const std::exception&) {\n    return;\n  }", "ListenerMessageTest"),

    ("F3: envelope does not check that params is an object", LISTENER, PARAMS_CHECK,
     "  if(false) {", "ListenerMessageTest"),

    ("F3: envelope does not check the id type", LISTENER, ID_CHECK,
     "    if(false) {", "ListenerMessageTest"),

    ("F3: envelope does not require a string method", LISTENER, METHOD_CHECK,
     "  if(false) {", "ListenerMessageTest"),

    ("F3: unknown method is ignored again (no -32601)", LISTENER, DISPATCH_TAIL,
     "  } else if(false) {", "ListenerMessageTest"),

    ("F3: notifications are answered too (-32601 whatever the id)", LISTENER, DISPATCH_TAIL,
     "  } else if(true) {", "ListenerMessageTest"),

    ("F3: absent params is not normalised to an empty object", LISTENER, NORMALISE,
     "  if(false) {", "ListenerMessageTest"),

    ("F3: tools/call does not check that arguments is an object", LISTENER, TOOLS_ARGUMENTS_CHECK,
     "  // mutated", "ListenerMessageTest"),

    ("F3: tools/call remap is not wrapped", LISTENER, TOOLS_REMAP,
     """  oatpp::Object<dto::ClientParamsToolsCall> callParams =
    m_remapper.remap<oatpp::Object<dto::ClientParamsToolsCall>>(call->params);
  do { if(false) { return; } } while(0);""", "ListenerMessageTest"),

    ("F3: prompts/list remap is not wrapped", LISTENER, handler_remap("prompts/list", "ClientParamsToolsList"),
     "  // mutated", "ListenerMessageTest"),

    ("F3: resources/list remap is not wrapped", LISTENER, handler_remap("resources/list", "ClientParamsResourceList"),
     "  // mutated", "ListenerMessageTest"),

    ("F3: initialize remap is not wrapped", LISTENER, handler_remap("initialize", "ClientParamsInitialize"),
     "  // mutated", "ListenerMessageTest"),

    ("F3: session thread does not guard the listener call", SESSION, LISTEN_GUARD,
     """    {
      auto event = m_inStream->read(std::chrono::milliseconds(5000));
      if(event) {
        listener->onEvent(*this, event);
      } else if (m_pinger) {
        m_pinger->onPing(*this);
      }
    }""", "ListenerMessageTest"),
]


def run(argv):
    return subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)


def build():
    return run(["cmake", "--build", BUILD, "-j6"]).returncode == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--list", action="store_true", help="list the mutations and exit")
    parser.add_argument("--only", type=int, metavar="N", help="run only mutation number N")
    args = parser.parse_args()

    if args.list:
        for i, (name, *_rest) in enumerate(MUTATIONS, 1):
            print(f"{i:2d}  {name}")
        return 0

    selected = [(i, m) for i, m in enumerate(MUTATIONS, 1)
                if args.only is None or i == args.only]
    if not selected:
        print(f"no such mutation: {args.only}", file=sys.stderr)
        return 2

    paths = sorted({m[1] for _i, m in selected})
    originals = {p: open(os.path.join(ROOT, p)).read() for p in paths}

    def restore():
        for p, text in originals.items():
            with open(os.path.join(ROOT, p), "w") as f:
                f.write(text)

    caught, missed, skipped = [], [], []
    try:
        for i, (name, path, old, new, test) in selected:
            restore()
            text = originals[path]
            if text.count(old) != 1:
                print(f"[{i:2d}] SKIPPED - pattern matched {text.count(old)} times in {path}: {name}")
                skipped.append(name)
                continue

            with open(os.path.join(ROOT, path), "w") as f:
                f.write(text.replace(old, new))

            if not build():
                print(f"[{i:2d}] SKIPPED - mutation does not compile: {name}")
                skipped.append(name)
                continue

            result = run(["./build/test/module-tests", f"--test={test}"])
            if result.returncode == 0:
                print(f"[{i:2d}] NOT CAUGHT: {name}")
                missed.append(name)
            else:
                summary = next((l.split("TEST[")[-1] for l in result.stdout.splitlines()
                                if "checks passed" in l), "test failed")
                print(f"[{i:2d}] caught    ({summary.strip()}) : {name}")
                caught.append(name)
    finally:
        restore()
        build()

    total = len(caught) + len(missed) + len(skipped)
    print(f"\n{len(caught)} caught, {len(missed)} not caught, {len(skipped)} skipped, of {total}")
    for label, items in (("NOT CAUGHT", missed), ("SKIPPED", skipped)):
        for item in items:
            print(f"  {label}: {item}")
    return 1 if (missed or skipped) else 0


if __name__ == "__main__":
    sys.exit(main())
