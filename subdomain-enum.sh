#!/bin/bash
sudo touch test.txt
sudo rm test.txt
red='\033[0;31m'
green='\033[38;5;208m'
nc='\033[0m' # No Color
figlet "Beginner-RC" | lolcat
    echo -e "${green} \t\t\tCoded BY : 00socrat00@github${nc}"

output="final-subdomain.txt"
subfinderoutput="subfinder.txt"
assetfinderoutput="assetfinder.txt"
amassoutput="amass.txt"
findomainoutput="findomain.txt"
knockoutput="knock.txt"
finaloutput="uniq_subdomains.txt"
githubsubdomain="githubsubdomain.txt"
vulnerabilities="possible_vulnerabilities"
# api 
github_api=""

# Colors
red='\033[0;31m'
green='\033[38;5;208m'
nc='\033[0m' # No Color
usage() {
     echo -e "\n"
    echo -e "${green}Usage: $0 -d domain -f file -s skip -o output${nc}"
    echo -e "${green}Options:${nc}"
    echo -e "\t-d  ${red}Single domain${nc}"
    echo -e "\t-f  ${red}File containing a list of domains${nc}"
    echo -e "\t-s  ${red}Tools to skip (e.g. subfinder,amass,findomain,knockpy,altdns,hook,github-subdomains)${nc}"
    echo -e "\t-o  ${red}Output file${nc}\n"
    echo -e "${green}Note: Either -d or -f option is required\n${nc}"
}


# Parse command-line options
while getopts "d:f:s:o:h" opt; do
    case $opt in
        d)
            domain="$OPTARG"
            ;;
        f)
            file="$OPTARG"
            ;;
        s)
            skip="$OPTARG"
            ;;
        o)
            output="$OPTARG"
            ;;
        h)
            usage
            exit 0
            ;;
        \?)
            usage
            exit 1
            ;;
    esac
done


perform_subdomain_enumeration() {
    local domain=$1


    # Remove duplicates
    if [ -z "$output" ]; then
        echo -e "${green}Output file not specified, using default: final-subdomain.txt${nc}"
    fi
    echo "Removing duplicates"
    cat ~/pentesting/targets/$domain/*.txt | sort | anew ~/pentesting/targets/$domain/$finaloutput
    rm ~/pentesting/targets/$domain/$subfinderoutput ~/pentesting/targets/$domain/$githubsubdomain ~/pentesting/targets/$domain/$assetfinderoutput ~/pentesting/targets/$domain/${domain}-subdomains.txt ~/pentesting/targets/$domain/censys_domains.txt ~/pentesting/targets/$domain/$amassoutput ~/pentesting/targets/$domain/$findomainoutput 




    echo -e "${green}[+] Running subdomain bruteforceing.${nc}\n"

    # loop through each line in the file "domain.txt"

    awk -v host=$domain '{print $0"."host}' ~/pentesting/lists/subdomains-top1million-20000.txt | anew -q ~/pentesting/targets/$domain/massdnslist.txt

    shuffledns -l ~/pentesting/targets/$domain/massdnslist.txt -r ~/massdns/lists/resolvers.txt -o ~/pentesting/targets/$domain/2deebsubdomain.txt

    if [ ! -s ~/pentesting/targets/$domain/2deebsubdomain.txt ]; then
       echo -e "${green}The file 2deebsubdomain.txt is empty.${nc}"
    else 
      for i in $(cat ~/pentesting/targets/$domain/2deebsubdomain.txt)
      do
             echo "$i"
            awk -v host="$i" '{print $0"."host}' ~/pentesting/lists/subdomains-top1million-20000.txt | anew ~/pentesting/targets/$domain/massdnslist2.txt
            shuffledns -l ~/pentesting/targets/$domain/massdnslist.txt -r ~/massdns/lists/resolvers.txt -o ~/pentesting/targets/$domain/3deebsubdomain.txt

      done
        if [ ! -s ~/pentesting/targets/$domain/3deebsubdomain.txt ]; then
           echo -e "The file ~/pentesting/targets/$domain/3deebsubdomain.txt is empty."
        else 
            for i in $(cat ~/pentesting/targets/$domain/3deebsubdomain.txt)
            do
                echo "$i"
                awk -v host="$i" '{print $0"."host}' ~/pentesting/lists/subdomains-top1million-20000.txt | anew ~/pentesting/targets/$domain/massdnslist3.txt
                shuffledns -l ~/pentesting/targets/$domain/massdnslist.txt -r ~/massdns/lists/resolvers.txt -o ~/pentesting/targets/$domain/4deebsubdomain.txt
            done
        fi
    fi

    rm ~/pentesting/targets/$domain/massdnslist.txt

    cat ~/pentesting/targets/$domain/*.txt | sort | anew ~/pentesting/targets/$domain/$finaloutput

    rm ~/pentesting/targets/$domain/2deebsubdomain.txt

    echo -e "${green}[+] Running httpx .${nc}\n"

    cat ~/pentesting/targets/$domain/$finaloutput | httpx -silent | grep "http" | cut -d "/" -f3 | anew -q ~/pentesting/targets/$domain/alive.txt
     
    echo -e "${green}[+] Running IP Enumerationg.${nc}\n"

    # Get ASN for domain name

    # dig $domain +short | awk '{
    #     match($0,/[0-9]{1,3}(\.[0-9]{1,3}){3}/)
    #     print substr($0, RSTART, RLENGTH)
    #   }' > ip_of_domain.txt 

    # firsttwooctatofip=$(cat  ip_of_domain.txt | cut -d'.' -f1-2 | head -n 1)

    # echo -e "${red}[+] Get ASN for $domain ${nc}\n"

    # asn=$(curl -s http://ip-api.com/json/$domain | jq -r .as | cut -d " " -f1)

    # echo -e "${red}[+] Get CIDR blocks for ASN $asn ${nc}\n"

    # cidr_list=$(whois -h whois.radb.net -- "-i origin $asn" | grep -Eo "([0-9.]+){4}/[0-9]+" | grep "$firsttwooctatofip")

    # for cidr in $cidr_list; do  
    #   ip_list=$(prips "$cidr")
    #   echo "CIDR: $cidr"
    #   for ip in $ip_list; do
    #     if ( grep -q "$ip" ip_of_domain.txt ) then
    #       echo "Specific IP found in CIDR: $cidr"
    #       echo "$cidr" | anew cidr.txt
    #       prips "$cidr" >> ips.txt
    #       break
    #     fi
    #   done
    # done

    echo -e "${red} \t [+] Get IPS of subdomains name ${nc}\n"


    cat ~/pentesting/targets/$domain/alive.txt | xargs  dig {} +short | awk '{
        match($0,/[0-9]{1,3}(\.[0-9]{1,3}){3}/)
        print substr($0, RSTART, RLENGTH)
      }' | anew ~/pentesting/targets/$domain/ips.txt

    echo -e "${red} \t [+] Get IPS using  shodan ${nc}\n"
    shodan search hostname:$domain | awk '{print $1}' | anew ~/pentesting/targets/$domain/ips.txt
    shodan search ssl:$domain.* 200 | awk '{print $1}' | anew ~/pentesting/targets/$domain/ips.txt
    shodan search ssl.cert.subject.CN:"$domain" 200 | awk '{print $1}' | anew ~/pentesting/targets/$domain/ips.txt

    echo -e "${red} \t [+] Running nrich on Ips List ${nc}\n"

    cat ~/pentesting/targets/$domain/ips.txt| nrich - | anew ~/pentesting/targets/$domain/nrich.txt

    echo -e "${red} \t [+] Get open ports${nc}\n"

    sudo masscan --port 1-65535  -iL ~/pentesting/targets/$domain/ips.txt --rate=10000 -oB ~/pentesting/targets/$domain/temp

    sudo masscan --readscan ~/pentesting/targets/$domain/temp |  awk '{print $NF":"$4}' |  cut -d/ -f1 | anew ~/pentesting/targets/$domain/open_ports.txt

    echo -e "\n${green}[+] Running URL Enumeration for $domain${nc}\n"

    echo -e "\n${green}[+] Get parameters of $domain ${nc}\n"

    python ~/pentesting/tools/ParamSpider/paramspider.py -d $domain -o ~/pentesting/targets/$domain/params.txt 

    echo -e "\n${green}[+] Running URL Waybackurls${nc}\n"

    echo "$domain" | waybackurls  | anew -q ~/pentesting/targets/$domain/urls.txt

    echo -e "\n${green}[+] Running URL gau ${nc}\n"

    echo "$domain" | gau | anew -q ~/pentesting/targets/$domain/urls.txt

    cat ~/pentesting/targets/$domain/params.txt ~/pentesting/targets/$domain/urls.txt | anew -q urls.txt

    echo -e "\n${green}[+] Get possible_vulnerabilities of $domain ${nc}\n"

    mkdir -p ~/pentesting/targets/$domain/$vulnerabilities

    cat ~/pentesting/targets/$domain/urls.txt | gf rce | anew -q ~/pentesting/targets/$domain/$vulnerabilities/rce.txt

    cat ~/pentesting/targets/$domain/urls.txt | gf xss | anew -q ~/pentesting/targets/$domain/$vulnerabilities/xss.txt

    cat ~/pentesting/targets/$domain/urls.txt | gf lfi | anew -q ~/pentesting/targets/$domain/$vulnerabilities/xss.txt

    cat ~/pentesting/targets/$domain/urls.txt | gf ssti | anew -q ~/pentesting/targets/$domain/$vulnerabilities/ssti.txt

    cat ~/pentesting/targets/$domain/urls.txt | gf ssrf | anew -q ~/pentesting/targets/$domain/$vulnerabilities/ssrf.txt

    cat ~/pentesting/targets/$domain/urls.txt | gf sqli | anew -q ~/pentesting/targets/$domain/$vulnerabilities/sqli.txt

    cat ~/pentesting/targets/$domain/urls.txt | gf ssrf | anew -q ~/pentesting/targets/$domain/$vulnerabilities/ssrf.txt

    cat ~/pentesting/targets/$domain/urls.txt | gf redirect | anew -q ~/pentesting/targets/$domain/$vulnerabilities/redirect.txt

    cat ~/pentesting/targets/$domain/urls.txt | gf idor | anew -q ~/pentesting/targets/$domain/$vulnerabilities/idor.txt

    echo -e "\n${green}[+] Start nuclei  ${nc}\n"

    cat ~/pentesting/targets/$domain/alive.txt | nuclei | anew ~/pentesting/targets/$domain/nuclei.txt
}


if [ -z "$output" ]; then
    echo -e "${green}Output file not specified, using default: final-subdomain.txt${nc}"
fi
# Check if no input is provided
if [[ -z $domain && -z $file ]]; then
    usage
    exit 1
fi
# Enumerate subdomains
if [[ ! -z $domain ]]; then
    mkdir -p ~/pentesting/targets/$domain

    if [[ ! "$skip" =~ "subfinder" ]]; then
        echo -e "\n${green}[+] Running subfinder for $domain${nc}\n"
        subfinder -d $domain -o ~/pentesting/targets/$domain/$subfinderoutput --silent
    fi
    if [[ ! "$skip" =~ "assetfinder" ]]; then
        echo -e "\n${green}[+] Running assetfinder for $domain${nc}\n"
        assetfinder $domain | tee -a ~/pentesting/targets/$domain/$assetfinderoutput
    fi
    if [[ ! "$skip" =~ "amass" ]]; then
        echo -e "\n${green}[+] Running amass for $domain${nc}\n"
        amass enum -d $domain -o ~/pentesting/targets/$domain/$amassoutput
    fi
    if [[ ! "$skip" =~ "findomain" ]]; then
        echo -e "\n${green}[+] Running findomain for $domain${nc}\n"
        findomain -t $domain -u ~/pentesting/targets/$domain/$findomainoutput
    fi
        if [[ ! "$skip" =~ "hook" ]]; then
        echo -e "\n${green}[+] Running findomain for $domain${nc}\n"
        python ~/pentesting/tools/hoOk/hoOk.py -t $domain 
    fi
           if [[ ! "$skip" =~ "github-subdomains" ]]; then
        echo -e "\n${green}[+] Running github-subdomains for $domain${nc}\n"
        python ~/pentesting/tools/github-search/github-subdomains.py -t $github_api -d $domain | anew ~/pentesting/targets/$domain/$githubsubdomain
    fi
    if [[ ! "$skip" =~ "knockpy" ]]; then
            echo "Running knockpy for $domain"
            python ~/pentesting/tools/knock/knockpy.py --no-http testphp.vulnweb.com -o ~/pentesting/targets/$domain/$knockoutput
    fi
    if [[ ! "$skip" =~ "sublister" ]]; then
        echo "Running sublister for $domain"
        sublist3r -d $domain -o ~/pentesting/targets/$domain/$output
    fi

    perform_subdomain_enumeration "$domain"

elif [[ ! -z $file ]]; then
    echo -e "${red} \n\t [+] Reading domains from file: ${green}$file ${nc} ${nc}\n"
    cat "$file" | while IFS= read -r domain || [ -n "$domain" ]; do
        echo "$domains"
        mkdir -p ~/pentesting/targets/$domain

        if [[ ! "$skip" =~ "subfinder" ]]; then
            echo -e "\n${green}[+] Running subfinder for $domain${nc}\n"
            subfinder -d $domain --silent | tee -a ~/pentesting/targets/$domain/$subfinderoutput 
        fi
        if [[ ! "$skip" =~ "assetfinder" ]]; then
            echo -e "\n${green}[+] Running assetfinder for $domain${nc}\n"
            assetfinder $domain | tee -a ~/pentesting/targets/$domain/$assetfinderoutput
        fi
        if [[ ! "$skip" =~ "amass" ]]; then
            echo -e "\n${green}[+] Running amass for $domain${nc}\n"
            amass enum -active -d $domain | tee -a  ~/pentesting/targets/$amassoutput 
        fi
        if [[ ! "$skip" =~ "findomain" ]]; then
            echo -e "\n${green}[+] Running findomain for $domain${nc}\n"
            findomain -t $domain | tee -a ~/pentesting/targets/$domain/$findomainoutput
        fi
        if [[ ! "$skip" =~ "knockpy" ]]; then
            echo "Running knockpy for $domain"
            python ~/pentesting/tools/knock/knockpy.py --no-http testphp.vulnweb.com | tee -a  ~/pentesting/targets/$domain/$knockoutput
        fi
        if [[ ! "$skip" =~ "sublister" ]]; then
            echo "Running sublister for $domain"
            sublist3r -d $domain | tee -a  ~/pentesting/targets/$domain/$output
        fi
        perform_subdomain_enumeration "$domain"
    done 
fi
