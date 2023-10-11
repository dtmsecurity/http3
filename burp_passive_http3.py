from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JTable, JScrollPane, JButton, BoxLayout
from javax.swing.table import DefaultTableModel
from java.net import URL
from java.awt import BorderLayout


class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def __init__(self):
        self.h3_endpoints = []

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("HTTP3 Extension")
        self.table_model = DefaultTableModel([ "HTTP3 Host", "HTTP3 Port", "Source", "Original Header"], 0)
        self.table = JTable(self.table_model)
        self.scroll_pane = JScrollPane(self.table)
        self.clear_button = JButton("Clear", actionPerformed=self.clear_table)
        self.panel = JPanel(BorderLayout())
        self.panel.add(self.scroll_pane, BorderLayout.CENTER)
        self.panel.add(self.clear_button, BorderLayout.SOUTH)
        self._callbacks.customizeUiComponent(self.panel)
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
        if not messageIsRequest:
            response_info = self._helpers.analyzeResponse(currentMessage.getResponse())
            headers = response_info.getHeaders()
            http_service = currentMessage.getHttpService()
            request_bytes = currentMessage.getRequest()
            request_info = self._helpers.analyzeRequest(http_service, request_bytes)
            url = request_info.getUrl().toString()
            hostname = URL(url).getHost()
            for header in headers:
                if header.strip().lower().startswith("alt-svc:"):
                    h3_signatures = ["h3", "h3-29"]
                    for h3_signature in h3_signatures:
                        if h3_signature in header.strip().lower():
                            try:
                                h3 = header.split(h3_signature + "=\"")[1].split("\"")[0]
                                h3_parts = h3.split(":")
                                h3_host = h3_parts[0].strip()
                                if h3_host == "":
                                    h3_host = hostname
                                h3_port = int(h3_parts[1].strip())
                                if (h3_host, h3_port) not in self.h3_endpoints:
                                    self.h3_endpoints.append((h3_host, h3_port))
                                    self.table_model.addRow([h3_host, h3_port, hostname, header])
                            except Exception as e:
                                print(e)
            pass

    def clear_table(self, event):
        while self.table_model.getRowCount() > 0:
            self.table_model.removeRow(0)
        self.h3_endpoints = []

    def getTabCaption(self):
        return "HTTP3"

    def getUiComponent(self):
        return self.panel
