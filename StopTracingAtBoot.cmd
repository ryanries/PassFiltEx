REM After the trace is stopped, look for the ETL file in C:\Windows\Debug.
logman stop PassFiltEx -ets
logman delete autosession\PassFiltEx -ets