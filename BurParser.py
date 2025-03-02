# -*- coding: utf-8 -*-

from burp import IBurpExtender, IHttpListener, ITab, IContextMenuFactory, IContextMenuInvocation, IScannerCheck
from javax.swing import JPanel, JTextArea, JScrollPane, BoxLayout, JButton, JLabel, JTextField, JCheckBox, JFileChooser, JSplitPane, JTabbedPane, JTable, JOptionPane, SwingUtilities, JMenuItem, JComboBox, JDialog, BorderFactory
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Dimension, GridLayout, FlowLayout, GridBagLayout, GridBagConstraints
from java.util import ArrayList, HashMap, LinkedHashMap, HashSet
from java.util.concurrent import ConcurrentHashMap, Executors, TimeUnit
from java.io import File, PrintWriter, BufferedWriter, FileWriter
from java.lang import Thread as JThread
from threading import Lock, Thread
from urlparse import urljoin, urlparse
import codecs
import re
import json
import time
import traceback
import os

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Initialize data structures with thread safety
        self.valid_dirs = ConcurrentHashMap()
        self.forbidden_dirs = ConcurrentHashMap()
        self.redirect_dirs = ConcurrentHashMap()
        self.error_pages = ConcurrentHashMap()
        self.processed_urls = ConcurrentHashMap()  # Track processed URLs to avoid duplicates
        self.extracted_paths = HashSet()  # For wordlist generation
        self.scan_scope = False  # Default to processing all requests
        self.is_running = True   # Extension active state
        self.lock = Lock()
        
        # Thread pool for async processing
        self.thread_pool = Executors.newFixedThreadPool(10)
        
        # Configure extension
        self._callbacks.setExtensionName("Burparser Pro")
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerScannerCheck(self)
        
        # Error page patterns (customizable)
        self.error_patterns = [
            r'(?i)not\s+found',
            r'(?i)404\s+error',
            r'(?i)access\s+denied',
            r'(?i)directory\s+listing\s+denied',
            r'(?i)page\s+not\s+found',
            r'(?i)file\s+not\s+found',
            r'(?i)server\s+error',
            r'(?i)internal\s+server\s+error',
            r'(?i)forbidden'
        ]
        
        # Content type whitelist
        self.valid_content_types = {
            'text/html',
            'application/json',
            'text/xml',
            'application/xml',
            'text/plain'
        }
        
        # Common file extensions to identify in paths
        self.common_extensions = [
            '.php', '.asp', '.aspx', '.jsp', '.jspx', '.do', '.action',
            '.html', '.htm', '.xhtml', '.shtml', '.json', '.xml', '.txt',
            '.js', '.css', '.cgi', '.pl', '.py', '.rb'
        ]
        
        # Initialize UI components
        self.setupUI()
        
        print("BurParser Pro Extension loaded successfully")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Respect the running state flag
        if not self.is_running:
            return
            
        # Process only if it's a response
        if not messageIsRequest:
            # Check if we should only process in-scope items
            if self.scan_scope and not self._callbacks.isInScope(messageInfo.getUrl()):
                return
                
            # Submit to thread pool for async processing
            self.thread_pool.submit(lambda: self.handle_http_response(messageInfo))

    def handle_http_response(self, messageInfo):
        try:
            # Extract response details
            response = messageInfo.getResponse()
            analyzed_response = self._helpers.analyzeResponse(response)
            
            # Get URL and remove query parameters
            url = str(messageInfo.getUrl())
            clean_url = self.clean_url(url)
            
            # Extract path for wordlist
            self.extract_path_for_wordlist(url)
            
            # Skip if already processed
            if self.processed_urls.putIfAbsent(clean_url, True) is not None:
                return
            
            # Extract important information
            status_code = analyzed_response.getStatusCode()
            headers = analyzed_response.getHeaders()
            content_type = self.get_content_type(headers)
            
            # Process according to status code
            if status_code == 200:
                self.handle_200_response(clean_url, response, analyzed_response, content_type)
            elif status_code == 403 or status_code == 401:
                self.handle_403_response(clean_url, headers, status_code)
            elif status_code >= 300 and status_code < 400:
                self.handle_redirect_response(clean_url, headers, content_type, status_code)
            elif status_code >= 500:
                self.handle_server_error(clean_url, status_code)
                
            # Update UI
            SwingUtilities.invokeLater(self.update_results_display)
                
        except Exception as e:
            self._callbacks.printError("Error processing message: %s\n%s" % (str(e), traceback.format_exc()))

    def extract_path_for_wordlist(self, url):
        """Extract path components and format them for effective wordlist generation."""
        try:
            parsed = urlparse(url)
            if not parsed.path or parsed.path == "/":
                return
            
            path_parts = [p for p in parsed.path.split('/') if p]
            current_path = ""
            
            for i, part in enumerate(path_parts):
                if not part:
                    continue
                
                # Add raw path segment
                self.extracted_paths.add(part)
                
                # Build progressive paths
                current_path += "/" + part
                self.extracted_paths.add(current_path.lstrip('/'))
                
                # Extract filename without extension if applicable
                if i == len(path_parts) - 1:
                    for ext in self.common_extensions:
                        if part.endswith(ext):
                            filename = part[:-len(ext)]
                            if filename:
                                self.extracted_paths.add(filename)
                            break
                
                # Extract numeric IDs separately
                if part.isdigit():
                    self.extracted_paths.add("ID-{}".format(part))

            # Extract parameters with potential sensitive data
            if parsed.query:
                params = parsed.query.split('&')
                for param in params:
                    if '=' in param:
                        key, value = param.split('=', 1)
                        self.extracted_paths.add(key)

                        # Detect sensitive values (UUID, Base64, hashes)
                        if re.match(r'^[0-9a-fA-F]{32,64}$', value):
                            self.extracted_paths.add("HASH-{}".format(key))
                        elif re.match(r'^[0-9]+$', value):
                            self.extracted_paths.add("NUM-" + str(key))
                        elif re.match(r'^[A-Za-z0-9+/=]{20,}$', value):  # Base64
                            self.extracted_paths.add("NUM-" + str(key))

        except Exception as e:
            self._callbacks.printError("Error extracting path: {}\n{}".format(str(e), traceback.format_exc()))


    def extract_url_parts(self, url):
        """Extract specific parts of the URL for better categorization"""
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')
        result = {
            'domain': parsed.netloc,
            'scheme': parsed.scheme,
            'path_depth': len([p for p in path_parts if p]),
        }
        
        if len(path_parts) >= 2:
            result['context'] = path_parts[1]
        if len(path_parts) >= 3:
            result['servlet'] = path_parts[2]
            
        return result

    def handle_200_response(self, url, response, analyzed_response, content_type):
        """Handle successful responses"""
        # Only process certain content types
        if content_type and any(valid_type in content_type.lower() for valid_type in self.valid_content_types):
            body_offset = analyzed_response.getBodyOffset()
            body = self._helpers.bytesToString(response[body_offset:])
            
            if not self.is_error_page(body):
                info = HashMap()
                info.put('status', 200)
                info.put('content_type', content_type)
                info.put('timestamp', time.time())
                info.put('size', len(body))
                info.put('url_parts', self.extract_url_parts(url))
                
                # Extract interesting elements from successful responses
                if 'html' in content_type.lower():
                    forms = self.extract_forms(body)
                    if forms:
                        info.put('forms', forms)
                        
                    api_endpoints = self.extract_api_endpoints(body)
                    if api_endpoints:
                        info.put('api_endpoints', api_endpoints)
                        
                    # Extract links and directory paths
                    self.extract_links_from_html(body, url)
                
                self.valid_dirs.put(url, info)
            else:
                # It's a 200 OK but looks like an error page
                info = HashMap()
                info.put('status', 200)
                info.put('is_error_page', True)
                info.put('content_type', content_type)
                info.put('timestamp', time.time())
                self.error_pages.put(url, info)
            
    def handle_403_response(self, url, headers, status_code):
        """Handle forbidden responses"""
        info = HashMap()
        info.put('status', status_code)
        info.put('headers', self.extract_security_headers(headers))
        info.put('timestamp', time.time())
        info.put('url_parts', self.extract_url_parts(url))
        self.forbidden_dirs.put(url, info)

    def handle_redirect_response(self, url, headers, content_type, status_code):
        """Handle redirect responses"""
        location = self.get_header_value(headers, "Location")
        if location:
            redirect_url = urljoin(url, location)
            info = HashMap()
            info.put('status', status_code)
            info.put('redirect_to', redirect_url)
            info.put('content_type', content_type)
            info.put('timestamp', time.time())
            info.put('url_parts', self.extract_url_parts(url))
            self.redirect_dirs.put(url, info)
            
            # Extract the path from redirect location for wordlist
            self.extract_path_for_wordlist(redirect_url)

    def handle_server_error(self, url, status_code):
        """Handle server error responses"""
        info = HashMap()
        info.put('status', status_code)
        info.put('timestamp', time.time())
        info.put('url_parts', self.extract_url_parts(url))
        self.error_pages.put(url, info)

    def extract_links_from_html(self, body, base_url):
        """Extract links from HTML content for wordlist generation"""
        # Extract href links
        href_pattern = r'href=["\'](.*?)["\']'
        hrefs = re.findall(href_pattern, body)
        
        # Extract src links
        src_pattern = r'src=["\'](.*?)["\']'
        srcs = re.findall(src_pattern, body)
        
        # Extract action URLs
        action_pattern = r'action=["\'](.*?)["\']'
        actions = re.findall(action_pattern, body)
        
        # Extract URLs from JavaScript
        js_pattern = r'["\'](/[^"\']*?)["\']|["\'](https?://[^"\']*)["\']'
        js_urls = re.findall(js_pattern, body)
        
        # Process all found URLs
        all_links = hrefs + srcs + actions
        for link_pair in js_urls:
            if link_pair[0]:
                all_links.append(link_pair[0])
            if link_pair[1]:
                all_links.append(link_pair[1])
        
        for link in all_links:
            if link.startswith('/') or link.startswith('http'):
                try:
                    abs_url = urljoin(base_url, link)
                    self.extract_path_for_wordlist(abs_url)
                except:
                    pass

    def extract_forms(self, body):
        """Extract form information from HTML"""
        forms = []
        form_pattern = r'<form\s+[^>]*>(.*?)</form>'
        form_matches = re.finditer(form_pattern, body, re.DOTALL | re.IGNORECASE)
        
        for match in form_matches:
            form_html = match.group(0)
            
            # Extract form action
            action_match = re.search(r'action=["\'](.*?)["\']', form_html)
            action = action_match.group(1) if action_match else ""
            
            # Extract form method
            method_match = re.search(r'method=["\'](.*?)["\']', form_html)
            method = method_match.group(1) if method_match else "GET"
            
            # Extract form inputs
            inputs = []
            input_pattern = r'<input\s+[^>]*>'
            input_matches = re.finditer(input_pattern, form_html)
            
            for input_match in input_matches:
                input_html = input_match.group(0)
                
                # Extract input name
                name_match = re.search(r'name=["\'](.*?)["\']', input_html)
                name = name_match.group(1) if name_match else ""
                
                # Extract input type
                type_match = re.search(r'type=["\'](.*?)["\']', input_html)
                input_type = type_match.group(1) if type_match else "text"
                
                if name:
                    inputs.append({'name': name, 'type': input_type})
                    # Add input names to wordlist
                    self.extracted_paths.add(name)
            
            forms.append({
                'action': action,
                'method': method,
                'inputs': inputs
            })
            
        return forms

    def extract_api_endpoints(self, body):
        """Extract potential API endpoints from JavaScript"""
        endpoints = []
        # Look for URLs in JS 
        api_pattern = r'["\'](/api/[^"\']+)["\']|["\'](https?://[^"\']+/api/[^"\']+)["\']'
        matches = re.finditer(api_pattern, body)
        
        for match in matches:
            endpoint = match.group(1) or match.group(2)
            if endpoint and endpoint not in endpoints:
                endpoints.append(endpoint)
                # Add to wordlist
                self.extract_path_for_wordlist(endpoint)
                
        return endpoints

    def is_error_page(self, body):
        """Enhanced error page detection"""
        if not body:
            return True
            
        # Check against error patterns
        for pattern in self.error_patterns:
            if re.search(pattern, body):
                return True
                
        # Check for common error page characteristics
        if len(body.strip()) < 100:  # Suspicious if too short
            return True
            
        return False

    def clean_url(self, url):
        """Remove query parameters and fragments from URL"""
        parsed = urlparse(url)
        cleaned = "%s://%s%s" % (parsed.scheme, parsed.netloc, parsed.path)
        # Ensure path ends with / if it's a directory path
        if not parsed.path.endswith('/') and '.' not in parsed.path.split('/')[-1]:
            cleaned += '/'
        return cleaned

    def get_content_type(self, headers):
        """Extract content type from headers"""
        for header in headers:
            if header.lower().startswith("content-type:"):
                return header.split(":", 1)[1].strip()
        return None

    def extract_security_headers(self, headers):
        """Extract security-related headers"""
        security_headers = HashMap()
        interesting_headers = [
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
            'content-security-policy',
            'strict-transport-security',
            'www-authenticate',
            'server',
            'x-powered-by'
        ]
        
        for header in headers:
            header_lower = header.lower()
            for sec_header in interesting_headers:
                if header_lower.startswith("%s:" % sec_header):
                    security_headers.put(sec_header, header.split(":", 1)[1].strip())
                    
        return security_headers

    def get_header_value(self, headers, header_name):
        """Get value of specific header"""
        for header in headers:
            if header.lower().startswith("%s:" % header_name.lower()):
                return header.split(":", 1)[1].strip()
        return None

    def setupUI(self):
        """Setup the extension's UI tab with enhanced interface"""
        self.tab = JPanel(BorderLayout())
        
        # Create a tabbed pane for different result categories
        tabbed_pane = JTabbedPane()
        
        # Create tables for different result types
        self.valid_dirs_table = self.create_table(["URL", "Content Type", "Size", "Timestamp"])
        self.forbidden_dirs_table = self.create_table(["URL", "Status", "Security Headers", "Timestamp"])
        self.redirect_dirs_table = self.create_table(["URL", "Redirects To", "Status", "Timestamp"])
        self.error_pages_table = self.create_table(["URL", "Status", "Timestamp"])
        self.wordlist_table = self.create_table(["Path Component", "Source"])
        
        # Add tables to tabbed pane
        tabbed_pane.addTab("Valid (200)", JScrollPane(self.valid_dirs_table))
        tabbed_pane.addTab("Forbidden", JScrollPane(self.forbidden_dirs_table))
        tabbed_pane.addTab("Redirects", JScrollPane(self.redirect_dirs_table))
        tabbed_pane.addTab("Errors", JScrollPane(self.error_pages_table))
        tabbed_pane.addTab("Wordlist", JScrollPane(self.wordlist_table))
        
        # Control panel
        control_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        # Create filter field
        self.filter_field = JTextField(20)
        self.filter_field.setToolTipText("Filter results by domain or path")
        
        # Create scope checkbox
        self.scope_checkbox = JCheckBox("In-Scope Only")
        self.scope_checkbox.addActionListener(lambda event: self.toggle_scope())
        
        # Create clear button
        clear_button = JButton("Clear Results")
        clear_button.addActionListener(lambda event: self.clear_results())
        
        # Create export button
        export_button = JButton("Export Results")
        export_button.addActionListener(lambda event: self.export_results())
        
        # Create filter button
        filter_button = JButton("Apply Filter")
        filter_button.addActionListener(lambda event: self.apply_filter())
        
        # Create wordlist export button
        wordlist_button = JButton("Export Wordlist")
        wordlist_button.addActionListener(lambda event: self.export_wordlist())
        
        # Create extract from targets button
        extract_targets_button = JButton("Extract from Targets")
        extract_targets_button.addActionListener(lambda event: self.extract_from_targets())
        
        # Add components to control panel
        control_panel.add(JLabel("Filter:"))
        control_panel.add(self.filter_field)
        control_panel.add(filter_button)
        control_panel.add(self.scope_checkbox)
        control_panel.add(clear_button)
        control_panel.add(export_button)
        control_panel.add(wordlist_button)
        control_panel.add(extract_targets_button)
        
        # Add components to main panel
        self.tab.add(control_panel, BorderLayout.NORTH)
        self.tab.add(tabbed_pane, BorderLayout.CENTER)
        
        # Add custom tab to Burp's UI
        self._callbacks.addSuiteTab(self)

    def create_table(self, columns):
        """Create a JTable with specified columns"""
        model = DefaultTableModel(columns, 0)
        table = JTable(model)
        table.setAutoCreateRowSorter(True)
        return table

    def toggle_scope(self):
        """Toggle scope-only processing"""
        self.scan_scope = self.scope_checkbox.isSelected()

    def clear_results(self):
        """Clear all collected results"""
        self.valid_dirs.clear()
        self.forbidden_dirs.clear()
        self.redirect_dirs.clear()
        self.error_pages.clear()
        self.processed_urls.clear()
        self.extracted_paths.clear()
        self.update_results_display()

    def apply_filter(self):
        """Apply filter to results"""
        self.update_results_display()

    def update_results_display(self):
        """Update all result tables"""
        try:
            filter_text = self.filter_field.getText().lower()
            
            # Update Valid Directories table
            self.update_table(self.valid_dirs_table, self.valid_dirs, filter_text, 
                lambda url, info: [
                    url, 
                    info.get('content_type', ""), 
                    str(info.get('size', 0)), 
                    time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info.get('timestamp', 0)))
                ]
            )
                
            # Update Forbidden Directories table
            self.update_table(self.forbidden_dirs_table, self.forbidden_dirs, filter_text, 
                lambda url, info: [
                    url, 
                    str(info.get('status', 403)), 
                    str(info.get('headers', {})), 
                    time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info.get('timestamp', 0)))
                ]
            )
                
            # Update Redirect Directories table
            self.update_table(self.redirect_dirs_table, self.redirect_dirs, filter_text, 
                lambda url, info: [
                    url, 
                    str(info.get('redirect_to', "")), 
                    str(info.get('status', 302)), 
                    time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info.get('timestamp', 0)))
                ]
            )
                
            # Update Error Pages table
            self.update_table(self.error_pages_table, self.error_pages, filter_text, 
                lambda url, info: [
                    url, 
                    str(info.get('status', "Unknown")), 
                    time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info.get('timestamp', 0)))
                ]
            )
            
            # Update Wordlist table
            self.update_wordlist_table(filter_text)
                
        except Exception as e:
            self._callbacks.printError("Error updating display: %s\n%s" % (str(e), traceback.format_exc()))

    def update_table(self, table, data_map, filter_text, row_mapper):
        """Update a table with filtered data"""
        model = table.getModel()
        model.setRowCount(0)
        
        for url in data_map.keySet():
            if filter_text and filter_text not in url.lower():
                continue
                
            info = data_map.get(url)
            row_data = row_mapper(url, info)
            model.addRow(row_data)

    def update_wordlist_table(self, filter_text):
        """Update wordlist table"""
        model = self.wordlist_table.getModel()
        model.setRowCount(0)
        
        for path in sorted(self.extracted_paths):
            if filter_text and filter_text not in path.lower():
                continue
            model.addRow([path, "Extracted"])

    def export_results(self):
        """Export results to JSON file"""
        try:
            # Convert Java HashMaps to Python dicts for JSON serialization
            results = self.prepare_export_data()
            
            # Use Java's JFileChooser
            file_chooser = JFileChooser()
            file_chooser.setSelectedFile(File("burparser_results.json"))
            
            if file_chooser.showSaveDialog(self.tab) == JFileChooser.APPROVE_OPTION:
                selected_file = file_chooser.getSelectedFile()
                file_path = selected_file.getAbsolutePath()
                
                # Ensure file has .json extension
                if not file_path.lower().endswith('.json'):
                    file_path += '.json'
                    
                with open(file_path, 'w') as f:
                    json.dump(results, f, indent=4)
                    
                JOptionPane.showMessageDialog(self.tab, 
                    "Results exported successfully to: %s" % file_path,
                    "Export Complete",
                    JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self.tab,
                "Error exporting results: %s" % str(e),
                "Export Error",
                JOptionPane.ERROR_MESSAGE)
            self._callbacks.printError("Error exporting results: %s\n%s" % (str(e), traceback.format_exc()))

    def export_wordlist(self):
        """Export discovered paths as a wordlist for tools like dirsearch/dirbuster"""
        try:
            # Use Java's JFileChooser
            file_chooser = JFileChooser()
            file_chooser.setSelectedFile(File("burparser_wordlist.txt"))
            
            if file_chooser.showSaveDialog(self.tab) == JFileChooser.APPROVE_OPTION:
                selected_file = file_chooser.getSelectedFile()
                file_path = selected_file.getAbsolutePath()
                
                # Ensure file has .txt extension
                if not file_path.lower().endswith('.txt'):
                    file_path += '.txt'
                
                # Open the export options dialog
                self.show_wordlist_export_options(file_path)
                    
        except Exception as e:
            JOptionPane.showMessageDialog(self.tab,
                "Error exporting wordlist: %s" % str(e),
                "Export Error",
                JOptionPane.ERROR_MESSAGE)
            self._callbacks.printError("Error exporting wordlist: %s\n%s" % (str(e), traceback.format_exc()))

    def show_wordlist_export_options(self, file_path):
        """Show dialog with wordlist export options"""
        dialog = JDialog(None, "Wordlist Export Options", True)
        dialog.setSize(400, 300)
        dialog.setLocationRelativeTo(self.tab)
        
        panel = JPanel(GridBagLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        constraints = GridBagConstraints()
        
        # Set up the constraints
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.weightx = 1.0
        constraints.gridx = 0
        constraints.gridy = 0
        constraints.gridwidth = 2
        
        # Add options
        panel.add(JLabel("Export Options:"), constraints)
        
        constraints.gridy = 1
        min_length_check = JCheckBox("Filter by minimum length")
        panel.add(min_length_check, constraints)
        
        constraints.gridy = 2
        constraints.gridwidth = 1
        panel.add(JLabel("Minimum length:"), constraints)
        
        constraints.gridx = 1
        min_length_field = JTextField("3", 5)
        min_length_field.setEnabled(False)
        panel.add(min_length_field, constraints)
        
        # Link checkbox to text field
        min_length_check.addActionListener(lambda e: min_length_field.setEnabled(min_length_check.isSelected()))
        
        constraints.gridx = 0
        constraints.gridy = 3
        constraints.gridwidth = 2
        common_ext_check = JCheckBox("Add common extensions to paths")
        panel.add(common_ext_check, constraints)
        
        constraints.gridy = 4
        constraints.gridwidth = 1
        panel.add(JLabel("Extension format:"), constraints)
        
        constraints.gridx = 1
        format_combo = JComboBox(["DIRECTORY", "DIRECTORY/", "/DIRECTORY/", "DIRECTORY.EXT"])
        format_combo.setEnabled(False)
        panel.add(format_combo, constraints)
        
        # Link checkbox to combo box
        common_ext_check.addActionListener(lambda e: format_combo.setEnabled(common_ext_check.isSelected()))
        
        constraints.gridx = 0
        constraints.gridy = 5
        constraints.gridwidth = 2
        filter_regex_check = JCheckBox("Filter using regex")
        panel.add(filter_regex_check, constraints)
        
        constraints.gridy = 6
        panel.add(JLabel("Regex pattern:"), constraints)
        
        constraints.gridy = 7
        regex_field = JTextField("^[a-zA-Z0-9_-]+$", 20)
        regex_field.setEnabled(False)
        panel.add(regex_field, constraints)
        
        # Link checkbox to text field
        filter_regex_check.addActionListener(lambda e: regex_field.setEnabled(filter_regex_check.isSelected()))
        
        # Add buttons
        constraints.gridy = 8
        constraints.gridwidth = 1
        constraints.fill = GridBagConstraints.NONE
        constraints.anchor = GridBagConstraints.CENTER
        constraints.weighty = 1.0
        
        export_button = JButton("Export", actionPerformed=lambda e: self.do_export_wordlist(
            file_path,
            min_length_check.isSelected(), 
            int(min_length_field.getText()),
            common_ext_check.isSelected(),
            format_combo.getSelectedItem(),
            filter_regex_check.isSelected(),
            regex_field.getText(),
            dialog
        ))
        panel.add(export_button, constraints)
        
        constraints.gridx = 1
        cancel_button = JButton("Cancel", actionPerformed=lambda e: dialog.dispose())
        panel.add(cancel_button, constraints)
        
        dialog.add(panel)
        dialog.setVisible(True)

    def do_export_wordlist(self, file_path, use_min_length, min_length, use_extensions, 
                          format_type, use_regex, regex_pattern, dialog):
        """Export wordlist with selected options"""
        try:
            # Create a filtered copy of the paths
            filtered_paths = set()
            
            # Apply filters
            for path in self.extracted_paths:
                # Skip empty paths
                if not path:
                    continue
                
                # Apply minimum length filter
                if use_min_length and len(path) < min_length:
                    continue
                
                # Apply regex filter
                if use_regex:
                    try:
                        if not re.match(regex_pattern, path):
                            continue
                    except:
                        # Invalid regex, skip this filter
                        pass
                
                filtered_paths.add(path)
            
            # Build final wordlist
            final_wordlist = set()
            
            # Add filtered paths in requested format
            for path in filtered_paths:
                # Add the base path
                final_wordlist.add(path)
                
                # Add with extensions if requested
                if use_extensions:
                    if format_type == "DIRECTORY":
                        final_wordlist.add(path)
                    elif format_type == "DIRECTORY/":
                        final_wordlist.add(path + "/")
                    elif format_type == "/DIRECTORY/":
                        final_wordlist.add("/" + path + "/")
                    elif format_type == "DIRECTORY.EXT":
                        for ext in self.common_extensions:
                            final_wordlist.add(path + ext)
            
            # Write to file
            with codecs.open(file_path, 'w', encoding='utf-8') as f:
                for path in sorted(final_wordlist):
                    f.write(path + "\n")
                    
            JOptionPane.showMessageDialog(self.tab, 
                "Wordlist exported successfully to: %s\nExported %d items." % (file_path, len(final_wordlist)),
                "Export Complete",
                JOptionPane.INFORMATION_MESSAGE)
                
            # Close the dialog
            dialog.dispose()
                
        except Exception as e:
            JOptionPane.showMessageDialog(self.tab,
                "Error exporting wordlist: %s" % str(e),
                "Export Error",
                JOptionPane.ERROR_MESSAGE)
            self._callbacks.printError("Error exporting wordlist: %s\n%s" % (str(e), traceback.format_exc()))

    def extract_from_targets(self):
        """Extract paths from site map/targets"""
        try:
            # Get all site map entries
            sitemap_entries = self._callbacks.getSiteMap(None)
            
            # Process each entry
            count = 0
            for entry in sitemap_entries:
                url = entry.getUrl()
                if url and self._callbacks.isInScope(url):
                    self.extract_path_for_wordlist(str(url))
                    count += 1
            
            # Update display
            self.update_results_display()
            
            JOptionPane.showMessageDialog(self.tab, 
                "Extracted paths from %d site map entries." % count,
                "Extraction Complete",
                JOptionPane.INFORMATION_MESSAGE)
                
        except Exception as e:
            JOptionPane.showMessageDialog(self.tab,
                "Error extracting from targets: %s" % str(e),
                "Extraction Error",
                JOptionPane.ERROR_MESSAGE)
            self._callbacks.printError("Error extracting from targets: %s\n%s" % (str(e), traceback.format_exc()))

    def prepare_export_data(self):
        """Prepare results data for export"""
        results = {
            "valid_directories": [],
            "forbidden_directories": [],
            "redirect_directories": [],
            "error_pages": [],
            "wordlist": sorted(list(self.extracted_paths))
        }
        
        # Convert Java HashMap to Python dict
        for url in self.valid_dirs.keySet():
            info = self.valid_dirs.get(url)
            entry = {"url": url}
            for key in info.keySet():
                value = info.get(key)
                if key == 'timestamp':
                    entry[key] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(value))
                else:
                    entry[key] = str(value)
            results["valid_directories"].append(entry)
            
        # Convert forbidden dirs
        for url in self.forbidden_dirs.keySet():
            info = self.forbidden_dirs.get(url)
            entry = {"url": url}
            for key in info.keySet():
                value = info.get(key)
                if key == 'timestamp':
                    entry[key] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(value))
                else:
                    entry[key] = str(value)
            results["forbidden_directories"].append(entry)
            
        # Convert redirect dirs
        for url in self.redirect_dirs.keySet():
            info = self.redirect_dirs.get(url)
            entry = {"url": url}
            for key in info.keySet():
                value = info.get(key)
                if key == 'timestamp':
                    entry[key] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(value))
                else:
                    entry[key] = str(value)
            results["redirect_directories"].append(entry)
            
        # Convert error pages
        for url in self.error_pages.keySet():
            info = self.error_pages.get(url)
            entry = {"url": url}
            for key in info.keySet():
                value = info.get(key)
                if key == 'timestamp':
                    entry[key] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(value))
                else:
                    entry[key] = str(value)
            results["error_pages"].append(entry)
            
        return results

    def doPassiveScan(self, baseRequestResponse):
        """Perform passive scanning (implements IScannerCheck)"""
        # Already handled in processHttpMessage
        return None
        
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Perform active scanning (implements IScannerCheck)"""
        # This extension only does passive scanning
        return None
        
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """Consolidate duplicate issues (implements IScannerCheck)"""
        # This extension only does passive scanning
        return 0
        
    def createMenuItems(self, invocation):
        """Create context menu items (implements IContextMenuFactory)"""
        context = invocation.getInvocationContext()
        
        if context == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE:
            menu_items = ArrayList()
            
            menu_item = JMenuItem("Extract Paths for Burparser")
            menu_item.addActionListener(lambda event: self.extract_paths_from_selected(invocation))
            
            menu_items.add(menu_item)
            return menu_items
            
        return None
        
    def extract_paths_from_selected(self, invocation):
        """Extract paths from selected targets in site map"""
        try:
            selected_messages = invocation.getSelectedMessages()
            
            if selected_messages and len(selected_messages) > 0:
                count = 0
                for message in selected_messages:
                    url = message.getUrl()
                    if url:
                        self.extract_path_for_wordlist(str(url))
                        count += 1
                
                # Update display
                SwingUtilities.invokeLater(self.update_results_display)
                
                JOptionPane.showMessageDialog(self.tab, 
                    "Extracted paths from %d selected items." % count,
                    "Extraction Complete",
                    JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            self._callbacks.printError("Error extracting from selection: %s\n%s" % (str(e), traceback.format_exc()))
            
    def getTabCaption(self):
        """Return the tab name (implements ITab)"""
        return "Burparser Pro"
        
    def getUiComponent(self):
        """Return the UI component (implements ITab)"""
        return self.tab

    def createMenuItems(self, invocation):
        """Create context menu items (implements IContextMenuFactory)"""
        context = invocation.getInvocationContext()
        
        if context == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE:
            menu_items = ArrayList()
            
            # Extract selected paths only
            extract_menu_item = JMenuItem("Extract Selected Paths for Burparser")
            extract_menu_item.addActionListener(lambda event: self.extract_paths_from_selected(invocation))
            
            # Extract entire subdirectory tree
            extract_tree_menu_item = JMenuItem("Extract Directory Tree for Burparser")
            extract_tree_menu_item.addActionListener(lambda event: self.extract_directory_tree(invocation))
            
            menu_items.add(extract_menu_item)
            menu_items.add(extract_tree_menu_item)
            return menu_items
            
        return None
        
    def extract_directory_tree(self, invocation):
        """Extract entire directory tree from selected nodes in site map"""
        try:
            selected_messages = invocation.getSelectedMessages()
            processed_urls = set()  # To avoid duplicates

            if selected_messages and len(selected_messages) > 0:
                # Get base URLs from selected messages
                base_urls = []
                for message in selected_messages:
                    url = message.getUrl().toString().encode('utf-8')  # 🔥 Fix here
                    if url:
                        base_urls.append(url)

                # Get all sitemap entries
                sitemap_entries = self._callbacks.getSiteMap(None)
                count = 0

                # Process each site map entry
                for entry in sitemap_entries:
                    entry_url = entry.getUrl().toString().encode('utf-8')  # 🔥 Fix here

                    # Check if this URL is under any of our base URLs
                    if entry_url not in processed_urls:
                        for base_url in base_urls:
                            if self.is_subpath_of(entry_url, base_url):
                                self.extract_path_for_wordlist(entry_url)
                                processed_urls.add(entry_url)
                                count += 1
                                break

                # Update display
                SwingUtilities.invokeLater(self.update_results_display)

                JOptionPane.showMessageDialog(self.tab, 
                    "Extracted paths from %d items in the directory tree." % count,
                    "Tree Extraction Complete",
                    JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            self._callbacks.printError("Error extracting directory tree: {}\n{}".format(str(e), traceback.format_exc()))


    def is_subpath_of(self, url, base_url):
        """Check if url is a subpath of base_url"""
        try:
            # Parse URLs
            parsed_url = urlparse(url)
            parsed_base = urlparse(base_url)
            
            # Check if domains match
            if parsed_url.netloc != parsed_base.netloc:
                return False
                
            # Get paths
            url_path = parsed_url.path
            base_path = parsed_base.path
            
            # Ensure base path ends with /
            if not base_path.endswith('/'):
                base_path += '/'
                
            # Check if url_path starts with base_path
            return url_path.startswith(base_path)
        except:
            return False

    def extract_all_subdirectories(self, base_url):
        """
        Extract and categorize all subdirectories under a base URL
        This performs active discovery of the directory structure
        """
        try:
            # Create a dialog to show progress
            dialog = JDialog(None, "Directory Tree Extraction", False)
            dialog.setSize(400, 150)
            dialog.setLocationRelativeTo(self.tab)
            
            panel = JPanel(BorderLayout(10, 10))
            panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
            
            status_label = JLabel("Extracting directory tree from: " + base_url)
            progress_label = JLabel("Processed: 0 URLs")
            
            panel.add(status_label, BorderLayout.NORTH)
            panel.add(progress_label, BorderLayout.CENTER)
            
            cancel_button = JButton("Cancel")
            panel.add(cancel_button, BorderLayout.SOUTH)
            
            dialog.add(panel)
            dialog.setVisible(True)
            
            # Run extraction in a separate thread
            extraction_thread = Thread(target=lambda: self.run_directory_extraction(
                base_url, 
                dialog, 
                progress_label,
                cancel_button
            ))
            extraction_thread.start()
            
        except Exception as e:
            self._callbacks.printError("Error in extract_all_subdirectories: %s\n%s" % (str(e), traceback.format_exc()))

    def run_directory_extraction(self, base_url, dialog, progress_label, cancel_button):
        """Run the directory extraction process"""
        try:
            # Track URLs to process and processed URLs
            to_process = [base_url]
            processed = set()
            results_count = 0
            is_cancelled = [False]  # Use list to allow modification in inner function
            
            # Set up cancel button
            cancel_button.addActionListener(lambda event: is_cancelled.__setitem__(0, True))
            
            while to_process and not is_cancelled[0]:
                # Get next URL to process
                current_url = to_process.pop(0)
                
                # Skip if already processed
                if current_url in processed:
                    continue
                    
                # Add to processed set
                processed.add(current_url)
                
                # Update progress
                results_count += 1
                SwingUtilities.invokeLater(lambda: progress_label.setText("Processed: %d URLs" % results_count))
                
                # Extract path for wordlist
                self.extract_path_for_wordlist(current_url)
                
                # Get site map entries for this URL
                current_entries = self._callbacks.getSiteMap(current_url)
                
                # Process child URLs
                for entry in current_entries:
                    child_url = str(entry.getUrl())
                    
                    # Skip if already processed
                    if child_url in processed:
                        continue
                        
                    # Check if child_url is under current_url
                    if self.is_subpath_of(child_url, current_url) and child_url != current_url:
                        to_process.append(child_url)
                        
                # Don't overwhelm the UI
                if results_count % 10 == 0:
                    SwingUtilities.invokeLater(self.update_results_display)
                    
            # Final UI update
            SwingUtilities.invokeLater(self.update_results_display)
            
            # Close dialog
            SwingUtilities.invokeLater(lambda: dialog.dispose())
            
            # Show completion message
            if not is_cancelled[0]:
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                    self.tab, 
                    "Completed directory tree extraction.\nProcessed %d URLs." % results_count,
                    "Extraction Complete",
                    JOptionPane.INFORMATION_MESSAGE
                ))
            else:
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                    self.tab, 
                    "Directory tree extraction cancelled.\nProcessed %d URLs." % results_count,
                    "Extraction Cancelled",
                    JOptionPane.INFORMATION_MESSAGE
                ))
                
        except Exception as e:
            self._callbacks.printError("Error in run_directory_extraction: %s\n%s" % (str(e), traceback.format_exc()))
            SwingUtilities.invokeLater(lambda: dialog.dispose())
