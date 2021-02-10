subdomain_scan() 
{
echo "Running Subdomain Scanning"

altdns -i domains.txt -o altd.txt -w /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
cat domains.txt | assetfinder | tee subdomains.txt
cat domains.txt | subfinder | anew subdomains.txt
dnsgen domains.txt | anew subdomains.txt
cat altd.txt | anew subdomains.txt
domains=$(cat domains.txt | tr '\n' ',' | sed 's/,$//')
amass enum -d $domains --passive -o amass-out.txt
cat amass-out.txt | anew subdomains.txt
var1=$(cat domains.txt | tr '\n' '|' | sed 's/|$//')
cat subdomains.txt | grep -E "$var1" | tee final-domains.txt && fndo=$(wc -l final-domains.txt | cut -d' ' -f1); echo "total $fndo domains found" | notify
}

resolve_domains()
{
echo "Resolving Domains"

cat final-domains.txt | massdns -r /usr/share/massdns/lists/resolvers.txt -t A -o S -w resolved-domains.txt && rsdo=$(wc -l resolved-domains.txt | cut -d' ' -f1); echo "total $rsdo live domains found" | notify
cut -d " " -f1 resolved-domains.txt | sed 's/.$//' | tee live-domains.txt
}

naabu_scan()
{
cat live-domains.txt | naabu -json | tee naabu-ports.json 
cat naabu-ports.json | grep 8080 | cut -d'"' -f4 | httpx -title -status-code -ports 8080 | tee naabu-sites.txt
cat naabu-ports.json | grep 8443 | cut -d'"' -f4 | httpx -title -status-code -ports 8443 | tee -a naabu-sites.txt; echo "Naabu Port Scan Completed"
}

run_httpx()
{
cat live-domains.txt | httpx -title -status-code | tee live-sites.txt
if ls -lha | grep naabu-sitess.txt
then 
    cat naabu-sites.txt | tee -a live-sites.txt
fi
cat live-sites.txt | cut -d' ' -f1 | tee ffuf-res.txt && ffres=$(wc -l ffuf-res.txt | cut -d' ' -f1); echo "total $ffres live websites found" | notify
}

run_masscan()
{
cat resolved-domains.txt | cut -d'A' -f2 | sed '/\.$/d' | sed -r 's/\s+//g' | sort -u | tee ip.txt
nohup masscan -iL ip.txt -p0-65535 --rate 10000 -oJ masscan.json; echo "Masscan completed" & 
}

run_jsfscan()
{
(nohup bash /usr/share/JSFScan.sh/JSFScan.sh -l ffuf-res.txt -s -e -r; echo "JSFScan Completed") & 
}

run_ffuf()
{
(nohup ffuf -u FUZZDOMAINS/FUZZ -w ffuf-res.txt:FUZZDOMAINS -w /usr/share/SecLists/Discovery/Web-Content/dicc.txt:FUZZ -mc 200 -fl 0,1 -fr 'Not Found','Unauthoriza','Forbidden' -t 10000 -of html -o ffuf-report.html; echo "Fffuf Completed" | notify) & 
}

run_nuclei()
{
(nohup cat ffuf-res.txt | nuclei -t cves -t exposed-panels -t fuzzing -t misconfiguration -t vulnerabilities -t default-logins -t exposed-tokens -t helpers -t takeovers -t workflows -t dns -t exposures -t miscellaneous -t technologies -o nucli-result.txt && nucl=$(wc -l nucli-result.txt | cut -d' ' -f1); echo "total $nucl issues found" | notify) & 
}
$1
