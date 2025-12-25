# -*- coding: utf-8 -*-

from burp import IBurpExtender, IHttpListener, ITab, IMessageEditorController
from javax.swing import JPanel, JTable, JScrollPane, JSplitPane, JButton
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout
import re
import json
import hashlib


# =========================
# Table selection listener
# =========================
class RowSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self.extender = extender

    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            self.extender._on_row_select()


# =========================
# Main Extension
# =========================
class BurpExtender(IBurpExtender, IHttpListener, ITab, IMessageEditorController):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName(
            "IDOR Hunter – Universal Behavioral Analyzer"
        )

        callbacks.registerHttpListener(self)

        self.findings = []
        self.current_request = None
        self.current_response = None

        self._build_ui()
        callbacks.addSuiteTab(self)

        print("[+] IDOR Hunter (universal) loaded cleanly")

    # ================= UI ================= #

    def _build_ui(self):
        self.panel = JPanel(BorderLayout())

        self.model = DefaultTableModel(
            ["URL", "Parameter", "Original", "Mutated", "Severity"], 0
        )

        self.table = JTable(self.model)
        self.table.getSelectionModel().addListSelectionListener(
            RowSelectionListener(self)
        )

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

        self.panel.add(export_btn, BorderLayout.NORTH)
        self.panel.add(JScrollPane(self.table), BorderLayout.CENTER)
        self.panel.add(split, BorderLayout.SOUTH)

    def getTabCaption(self):
        return "IDOR Hunter"

    def getUiComponent(self):
        return self.panel

    # ========== IMessageEditorController ========== #

    def getHttpService(self):
        if self.current_request:
            return self.current_request.getHttpService()
        return None

    def getRequest(self):
        if self.current_request:
            return self.current_request.getRequest()
        return None

    def getResponse(self):
        return self.current_response

    # ================= HTTP Listener ================= #

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        try:
            request = messageInfo.getRequest()
            response = messageInfo.getResponse()
            if not response:
                return

            req_info = self.helpers.analyzeRequest(request)
            url = req_info.getUrl().toString()

            if self._is_static(url) or not self._is_safe_endpoint(url):
                return

            body = self._get_body(request)
            req_str = self.helpers.bytesToString(request)

            params = self._extract_id_params(req_str)
            if not params:
                return

            for param, value in params:
                mutated_value = self._mutate_numeric(value)
                if not mutated_value:
                    continue

                mutated_req = self._mutate_param(req_str, param, value, mutated_value)
                if not mutated_req:
                    continue

                attack_req = self.helpers.stringToBytes(mutated_req)
                resp = self.callbacks.makeHttpRequest(
                    messageInfo.getHttpService(),
                    attack_req
                )

                self._analyze(messageInfo, resp, url, param, value, mutated_value)
                break  # single mutation (safety)

        except:
            return

    # ================= Analysis ================= #

    def _analyze(self, original, mutated, url, param, old, new):
        try:
            o_resp = original.getResponse()
            m_resp = mutated.getResponse()
            if not m_resp:
                return

            o_body = self.helpers.bytesToString(o_resp)
            m_body = self.helpers.bytesToString(m_resp)

            if self._fingerprint(o_body) == self._fingerprint(m_body):
                return  # no behavioral difference

            severity = self._score_severity(m_body)

            self.findings.append({
                "url": url,
                "parameter": param,
                "original": old,
                "mutated": new,
                "severity": severity,
                "request": mutated.getRequest(),
                "response": m_resp
            })

            self.model.addRow([url, param, old, new, severity])

            print("[!] Potential IDOR:", url, param, old, "→", new)

        except:
            return

    # ================= Universal Heuristics ================= #

    def _extract_id_params(self, text):
        results = []

        # Matches: id=123, user_id=123, processor_id=123 (2–7 digits)
        pattern = re.compile(
            r'([a-zA-Z0-9_]*_id|id)\s*=\s*["\']?(\d{2,7})',
            re.IGNORECASE
        )

        for match in pattern.findall(text):
            results.append(match)

        return list(set(results))

    def _mutate_param(self, req, param, old, new):
        pattern = re.compile(
            r'(' + re.escape(param) + r'\s*=\s*)' + re.escape(old),
            re.IGNORECASE
        )

        mutated, count = pattern.subn(r'\1' + new, req, 1)
        if count == 0:
            return None
        return mutated

    def _mutate_numeric(self, value):
        try:
            return str(int(value) + 1)
        except:
            return None

    def _fingerprint(self, body):
        # Content fingerprinting (universal)
        cleaned = re.sub(r'\s+', '', body)
        return hashlib.md5(cleaned.encode('utf-8')).hexdigest()

    def _score_severity(self, body):
        body = body.lower()
        sensitive = ["email", "phone", "address", "account", "role", "admin"]
        hits = sum(1 for s in sensitive if s in body)

        if hits >= 2:
            return "High"
        if hits == 1:
            return "Medium"
        return "Low"

    # ================= Utils ================= #

    def _get_body(self, request):
        info = self.helpers.analyzeRequest(request)
        return self.helpers.bytesToString(request[info.getBodyOffset():])

    def _is_static(self, url):
        return any(url.lower().endswith(x) for x in [
            ".js", ".css", ".png", ".jpg", ".svg", ".woff", ".ico"
        ])

    def _is_safe_endpoint(self, url):
        blacklist = ["logout", "delete", "remove", "payment", "transfer", "reset"]
        for x in blacklist:
            if x in url.lower():
                return False
        return True

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

        self.req_viewer.setMessage(finding["request"], True)
        self.res_viewer.setMessage(finding["response"], False)

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
