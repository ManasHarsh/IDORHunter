# -*- coding: utf-8 -*-
from burp import (
    IBurpExtender,
    IHttpListener,
    ITab,
    IMessageEditorController
)

from javax.swing import (
    JPanel,
    JTable,
    JScrollPane,
    JSplitPane,
    JButton
)

from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout
import re
import json


class BurpExtender(IBurpExtender, IHttpListener, ITab, IMessageEditorController):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName(
            "IDOR Hunter – Behavioral Object Access Analyzer"
        )

        callbacks.registerHttpListener(self)

        self.findings = []
        self.current_request = None
        self.current_response = None

        self._build_ui()
        callbacks.addSuiteTab(self)

        print("[+] IDOR Hunter loaded successfully")

    # ================= UI ================= #

    def _build_ui(self):
        self.main_panel = JPanel(BorderLayout())

        self.table_model = DefaultTableModel(
            ["URL", "Original ID", "Mutated ID", "Δ Length", "Severity"], 0
        )

        self.table = JTable(self.table_model)
        self.table.getSelectionModel().addListSelectionListener(
            lambda e: self._on_row_select()
        )

        table_scroll = JScrollPane(self.table)

        self.req_viewer = self.callbacks.createMessageEditor(self, True)
        self.res_viewer = self.callbacks.createMessageEditor(self, False)

        split = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            self.req_viewer.getComponent(),
            self.res_viewer.getComponent()
        )
        split.setResizeWeight(0.5)

        export_btn = JButton(
            "Export Findings (JSON)",
            actionPerformed=self._export
        )

        self.main_panel.add(export_btn, BorderLayout.NORTH)
        self.main_panel.add(table_scroll, BorderLayout.CENTER)
        self.main_panel.add(split, BorderLayout.SOUTH)

    def getTabCaption(self):
        return "IDOR Hunter"

    def getUiComponent(self):
        return self.main_panel

    # ========== IMessageEditorController ========= #

    def getHttpService(self):
        return self.current_request.getHttpService()

    def getRequest(self):
        return self.current_request.getRequest()

    def getResponse(self):
        return self.current_response

    # ================= Listener ================= #

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        request = messageInfo.getRequest()
        response = messageInfo.getResponse()
        if not response:
            return

        req_info = self.helpers.analyzeRequest(request)
        url = req_info.getUrl().toString().lower()

        if self._is_static(url) or not self._is_safe_endpoint(url):
            return

        body = self._get_body(request)

        ids = set()
        ids.update(self._extract_ids(url + body))
        ids.update(self._extract_json_ids(body))

        for oid in ids:
            mid = self._mutate_id(oid)
            if not mid or mid == oid:
                continue

            new_req = self.helpers.bytesToString(request).replace(oid, mid)
            attack_req = self.helpers.stringToBytes(new_req)

            resp = self.callbacks.makeHttpRequest(
                messageInfo.getHttpService(),
                attack_req
            )

            self._analyze(messageInfo, resp, url, oid, mid)
            break  # safety: only one mutation per request

    # ================= Analysis ================= #

    def _analyze(self, original, mutated, url, oid, mid):
        o_resp = original.getResponse()
        m_resp = mutated.getResponse()

        delta = abs(len(o_resp) - len(m_resp))
        if delta < 10:
            return

        severity = self._score_severity(m_resp, delta)

        self.findings.append({
            "url": url,
            "original_id": oid,
            "mutated_id": mid,
            "delta": delta,
            "severity": severity,
            "request": mutated.getRequest(),
            "response": m_resp
        })

        self.table_model.addRow([
            url,
            oid,
            mid,
            delta,
            severity
        ])

        print("[!] Potential IDOR:", url, oid, "→", mid)

    # ================= Severity ================= #

    def _score_severity(self, response, delta):
        text = self.helpers.bytesToString(response).lower()
        sensitive = [
            "email", "phone", "address",
            "role", "balance", "account", "admin"
        ]

        hits = sum(1 for s in sensitive if s in text)

        if hits >= 2 and delta > 200:
            return "High"
        if hits >= 1:
            return "Medium"
        return "Low"

    # ================= ID Extraction ================= #

    def _extract_ids(self, text):
        ids = []

        # 1. Path-based numeric IDs (/users/123456)
        ids += re.findall(r"/(\d{2,7})", text)

        # 2. Query/body parameters (*_id=123456)
        ids += re.findall(
            r"(?:^|[?&\"'])"
            r"(?:[a-zA-Z0-9_]*_id|id)"
            r"[\"']?\s*[:=]\s*[\"']?(\d{2,7})",
            text,
            re.IGNORECASE
        )

        # 3. UUIDs
        ids += re.findall(
            r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
            text.lower()
        )

        return list(set(ids))

    def _extract_json_ids(self, body):
        ids = []

        try:
            data = json.loads(body)

            def walk(obj):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if isinstance(v, int) and 2 <= len(str(v)) <= 7:
                            if k.lower().endswith("_id") or k.lower() == "id":
                                ids.append(str(v))
                        walk(v)
                elif isinstance(obj, list):
                    for i in obj:
                        walk(i)

            walk(data)
        except:
            pass

        return ids

    # ================= Mutation ================= #

    def _mutate_id(self, oid):
        try:
            if oid.isdigit():
                return str(int(oid) + 1)
            if "-" in oid:
                parts = oid.split("-")
                parts[-1] = parts[-1][::-1]
                return "-".join(parts)
        except:
            return None

    # ================= Utils ================= #

    def _get_body(self, request):
        info = self.helpers.analyzeRequest(request)
        return self.helpers.bytesToString(
            request[info.getBodyOffset():]
        )

    def _is_static(self, url):
        return any(url.endswith(x) for x in [
            ".js", ".css", ".png", ".jpg",
            ".svg", ".woff", ".ico"
        ])

    def _is_safe_endpoint(self, url):
        blacklist = [
            "logout", "delete", "remove",
            "payment", "transfer", "reset"
        ]
        return not any(x in url for x in blacklist)

    # ================= UI ================= #

    def _on_row_select(self):
        row = self.table.getSelectedRow()
        if row < 0:
            return

        finding = self.findings[row]

        self.current_request = DummyRequest(
            finding["request"],
            self.callbacks.getHttpService()
        )
        self.current_response = finding["response"]

        self.req_viewer.setMessage(
            finding["request"], True
        )
        self.res_viewer.setMessage(
            finding["response"], False
        )

    def _export(self, event):
        print(json.dumps(self.findings, indent=2))


class DummyRequest(object):
    def __init__(self, req, svc):
        self.req = req
        self.svc = svc

    def getRequest(self):
        return self.req

    def getHttpService(self):
        return self.svc
