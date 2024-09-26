Use within the Next-Gen SIEM Advanced event Search
```
"#event_simpleName" = DnsRequest
| ComputerName = ?ComputerName
| !cidr(IP4Records, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/32", "169.254.0.0/16", "0.0.0.0/32"])
| !cidr(FirstIP4Record, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/32", "169.254.0.0/16", "0.0.0.0/32"])
| !in(field="DomainName", values=[
"*.microsoft.com",
"*.live.com",
"*.microsoftonline.com",
"*.office.com",
"*.office.net",
"*.googleapis.com",
"*.google.com",
"*.office365.com",
"*.gstatic.com",
"*.outlook.com",
"*.microsoft",
"*.bing.com",
"*.msftauthimages.net",
"*.microsoftapp.net",
"*.googleadservices.com",
"*.adobe.com",
"*.walkme.com",
"*.microsoftazuread-sso.com",
"*.google-analytics.com",
"*.doubleclick.net",
"*.skype.com",
"aadcdn.*",
"*.msn.com",
"*.acrobat.com",
"*.adobe.io",
"*.arpa",
"*.arpa.",
"*.googlesyndication.com",
"*.windows.net",
"*.windows.com",
"*.msedge.net"
])
| groupBy([DomainName], function=collect([FirstIP4Record,IP4Records]))
```
