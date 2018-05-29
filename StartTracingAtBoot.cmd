REM This will start ETL tracing of PassFiltEx at the next reboot.
REM The ETL file can be opened with various tools, such as Microsoft Message Analyzer.
REM After the trace is stopped, look for the ETL file in C:\Windows\Debug.
logman create trace autosession\PassFiltEx -o %SystemRoot%\Debug\PassFiltEx.etl -p "{07d83223-7594-4852-babc-784803fdf6c5}" 0xFFFFFFFF -ets