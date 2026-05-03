"""
Patch AsyncTCP-esphome to null-check the malloc()s in lwIP callbacks.

Upstream 2.1.4 dereferences the result of malloc(sizeof(lwip_event_packet_t))
without checking for NULL in _tcp_clear_events / _tcp_connected / _tcp_poll /
_tcp_recv / _tcp_sent / _tcp_error / _tcp_dns_found / _tcp_accept. When lwIP
heap is exhausted (which can and does happen on a single-core ESP32-C3 under
sustained connection storms) the next field write is a Store access fault in
the tcpip thread and the device reboots.

We inject an early-return after each malloc. For _tcp_recv we return ERR_MEM
when there is still a pbuf attached so lwIP retains the data and retries
later; in every other path losing one event is acceptable.

The patch is idempotent — it tags the file with a sentinel marker so repeated
builds don't double-patch.
"""

Import("env")  # noqa: F821  (provided by PlatformIO)

import os
import re
import sys

SENTINEL = "// HoneyOpus: null-check malloc patch v3\n"


def patch_file(path: str) -> bool:
    if not os.path.isfile(path):
        return False
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    if SENTINEL in src:
        return False

    pattern = re.compile(
        r"(    lwip_event_packet_t \* e = \(lwip_event_packet_t \*\)malloc\(sizeof\(lwip_event_packet_t\)\);\n)"
    )

    # Function signature -> return statement on NULL.
    # _tcp_recv must return ERR_MEM when pb != NULL so lwIP retains the pbuf.
    # _tcp_error / _tcp_dns_found return void.
    fn_returns = {
        "_tcp_clear_events": "if (!e) { return ERR_OK; }\n",
        "_tcp_connected":    "if (!e) { return ERR_OK; }\n",
        "_tcp_poll":         "if (!e) { return ERR_OK; }\n",
        "_tcp_recv":         "if (!e) { return pb ? ERR_MEM : ERR_OK; }\n",
        "_tcp_sent":         "if (!e) { return ERR_OK; }\n",
        "_tcp_error":        "if (!e) { return; }\n",
        "_tcp_dns_found":    "if (!e) { return; }\n",
        "_tcp_accept":       "if (!e) { return ERR_OK; }\n",
    }

    out = []
    last = 0
    fn_re = re.compile(r"\b(_tcp_[a-z_]+)\s*\(", re.MULTILINE)

    # Walk each malloc, find the enclosing function name by scanning backwards.
    for m in pattern.finditer(src):
        # Find nearest function definition before this malloc.
        prefix = src[:m.start()]
        # Only consider definitions: 'static <ret> _tcp_xxx(' or 'static void _tcp_xxx('.
        candidates = list(re.finditer(
            r"^\s*static\s+[\w:* ]+?\s+(_tcp_[a-z_]+)\s*\(",
            prefix, re.MULTILINE))
        if not candidates:
            continue
        fn_name = candidates[-1].group(1)
        guard = fn_returns.get(fn_name)
        if not guard:
            continue
        out.append(src[last:m.end()])
        out.append("    " + guard)
        last = m.end()
    out.append(src[last:])
    new_src = "".join(out)

    # Second pass: NULL-guard the static dispatchers that lwIP / async_tcp
    # call. After AsyncServer::end() sets tcp_arg(pcb, NULL) there can still
    # be a pending SYN in flight whose accept callback fires with arg=NULL;
    # _s_accept then does reinterpret_cast<AsyncServer*>(NULL)->_accept and
    # we crash with a Load access fault. Same risk for the other dispatchers.
    static_guards = [
        ("int8_t AsyncServer::_s_accept(void * arg, tcp_pcb * pcb, int8_t err){\n",
         "    if (!arg) { if (pcb) tcp_abort(pcb); return ERR_ABRT; }\n"),
        ("int8_t AsyncServer::_s_accepted(void *arg, AsyncClient* client){\n",
         "    if (!arg) { return ERR_OK; }\n"),
        ("int8_t AsyncClient::_s_connected(void * arg, void * pcb, int8_t err){\n",
         "    if (!arg) { return ERR_OK; }\n"),
        ("int8_t AsyncClient::_s_lwip_fin(void * arg, struct tcp_pcb * pcb, int8_t err) {\n",
         "    if (!arg) { return ERR_OK; }\n"),
    ]
    for sig, guard in static_guards:
        if sig in new_src and (sig + guard) not in new_src:
            new_src = new_src.replace(sig, sig + guard, 1)

    # Third pass: clamp _tcp_recved_api against the lwIP
    #   tcp_update_rcv_ann_wnd: new_rcv_ann_wnd <= 0xffff
    # assert. ESP-IDF lwIP keeps a 16-bit announced receive window; if
    # AsyncTCP calls tcp_recved() with a size that, added to the current
    # pcb->rcv_ann_wnd, exceeds 0xFFFF, the assert fires and the device
    # panics. This is reachable e.g. on connection teardown when a small
    # tcp_recved(1) is issued while the window is already fully open
    # (rcv_ann_wnd == 0xFFFF). Clamp the call so we never overflow.
    old_recved = (
        "static err_t _tcp_recved_api(struct tcpip_api_call_data *api_call_msg){\n"
        "    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;\n"
        "    msg->err = ERR_CONN;\n"
        "    if(msg->closed_slot == -1 || !_closed_slots[msg->closed_slot]) {\n"
        "        msg->err = 0;\n"
        "        tcp_recved(msg->pcb, msg->received);\n"
        "    }\n"
        "    return msg->err;\n"
        "}\n"
    )
    new_recved = (
        "static err_t _tcp_recved_api(struct tcpip_api_call_data *api_call_msg){\n"
        "    tcp_api_call_t * msg = (tcp_api_call_t *)api_call_msg;\n"
        "    msg->err = ERR_CONN;\n"
        "    if(msg->closed_slot == -1 || !_closed_slots[msg->closed_slot]) {\n"
        "        msg->err = 0;\n"
        "        size_t _ho_recvd = msg->received;\n"
        "        if (msg->pcb) {\n"
        "            uint32_t _ho_wnd = (uint32_t)msg->pcb->rcv_ann_wnd;\n"
        "            if (_ho_wnd >= 0xFFFFu) _ho_recvd = 0;\n"
        "            else if (_ho_wnd + _ho_recvd > 0xFFFFu) _ho_recvd = 0xFFFFu - _ho_wnd;\n"
        "        }\n"
        "        if (_ho_recvd) tcp_recved(msg->pcb, _ho_recvd);\n"
        "    }\n"
        "    return msg->err;\n"
        "}\n"
    )
    if old_recved in new_src:
        new_src = new_src.replace(old_recved, new_recved, 1)

    if new_src == src:
        return False

    new_src = SENTINEL + new_src
    with open(path, "w", encoding="utf-8") as f:
        f.write(new_src)
    return True


def main():
    project_dir = env["PROJECT_DIR"]  # noqa: F821
    candidates = [
        os.path.join(project_dir, ".pio", "libdeps", env["PIOENV"],  # noqa: F821
                     "AsyncTCP-esphome", "src", "AsyncTCP.cpp"),
    ]
    for path in candidates:
        if patch_file(path):
            print(f"[honeyopus] patched {path}")
        elif os.path.isfile(path):
            print(f"[honeyopus] {path} already patched")


main()
