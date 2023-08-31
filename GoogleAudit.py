import os
import time
import pwinput
import time
import json
from dns.resolver import resolve
from dns.exception import DNSException
from playwright.sync_api import sync_playwright, TimeoutError as pwto
from logger import Log

def analyze(results):
    total = len(results)
    count = 1
    with open('controls.json', 'r') as f:
        controls = json.load(f)
    log.entry('\n--- Beginning Analysis ---\n', 'OUT')
    comp = 'None'
    for result in results.values():
        for control in controls:
            if control['controlNumber'] == result[0]:
                cend = control['expected'][-3:]
                rend = result[1][-3:]
                if cend in [' ON', 'OFF'] or control['expected'] == result[1]:
                    if cend == rend:
                        result[2] = True
                    print(f'\n({count}/{total}) -- Control {result[0]} --\n[*] Automatically validated')
                    log.entry(f'Control {result[0]}: Automatically validated -> Expected: {control["expected"]}, Found: {result[1]}, Compliance: {result[2]}', 'DEBUG')
                elif result[1] == 'FAILED -> MANUALLY VALIDATE':
                    result[2] = False
                else:
                    log.entry(f'\n({count}/{total}) -- Control {result[0]}--', 'OUT')
                    log.entry(f'Description: {control["controlTitle"]}\n', 'OUT')
                    expected = control['expected']
                    if '&lt' in expected:
                        expected = expected.replace('&lt', '<')
                    if '&gt' in expected:
                        expected = expected.replace('&gt', '>')
                    print(f"Expected result: {expected}\nFound result:    {result[1]}")
                    while comp not in ['y','n']:
                        comp = input('\n[?] Compliant? (y/n): ')
                        if comp.lower() == 'y':
                            result[2] = True
                        elif comp.lower() == 'n':
                            result[2] = False   
                        else:
                            print('  [-] Enter y or n only, try again')
                    log.entry(f'Control {result[0]}: Manually validated -> {result[2]}', 'DEBUG')
                    comp = 'None' 
        count+=1
    return results

def run(playwright):
    results = {}
    index = 0
    control = []

    # Initialize Chrome puppet
    chromium = playwright.chromium
    browser = chromium.launch(headless=False) # Create a new incognito Chrome browser, set 'headless=False' to view UI
    context = browser.new_context(user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36')
    page = context.new_page()

    page.set_viewport_size({"width": 1920, "height": 1080}) # Set size of Chrome windows

    # Login section, ask user for email and pw to Google, fills out and submits, uses 'pwinput' to mask input
    username = input('[?] Email: ') # CHANGE
    log.entry(f"Email: {username}", 'DEBUG')
    password = pwinput.pwinput('[?] Password: ')
    page.goto("https://admin.google.com/")
    page.get_by_label("Email or phone").fill(username) 
    page.get_by_role("button", name="Next").click()
    input('[!] If CAPTCHA is required, enter CAPTCHA and press enter when ready to continue')
    page.get_by_label("Enter your password").fill(password)
    page.locator("#passwordNext").click()
    input("[!] If MFA is enabled, approve and press enter when ready to continue") # Wait for use to accept MFA request before proceeding to site
    time.sleep(3)

    print("\n--- Beginning Data Collection ---\n")
    page.goto('https://admin.google.com/ac/managedsettings/435070579839/sharing?hl=en;External')
    form = page.get_by_label('External sharing options for primary calendars',exact=True)
    form.wait_for()
    text = form.inner_text().split('\n')
    for x in range(len(text)):
        if text[x] == 'External sharing options for primary calendars':
            org = text[x+2]
    if not org:
        log.entry('[!] Fatal: Organization name not found', 'ERROR')
        exit()
    else:
        org = org[8:-41]
    log.entry(f'Org name: {org}', 'DEBUG')
    #----TESTING NEW CONTROLS----
    # return results
    #----END TESTING----

    with open('controls.csv', mode = 'r') as file:
        for line in file:
            if not line[0] == '#':
                line = line.strip().split(';')
                for x in range(len(line)):
                    if '$ORG' in line[x]:
                        line[x] = line[x].replace('$ORG', org)
                control.append(line)

    for current in control:
        control_num = current[0]
        url = current[1]
        prefix = current[2]
        name = current[3]
        search_string = current[4]
        log.entry('[*] Fetching control ' + control_num, 'OUT')
        # If current url is the same as previous url, this line is skipped because it is looking at the same page, otherwise page goes to the url
        if index > 0:
            if control[index][1] != control[index-1][1]:
                page.goto(url)
                time.sleep(3)
        else: page.goto(url)
        try:
            form = page.get_by_label(name, exact=True)
            form.wait_for()
            text = form.inner_text().split("\n") #Changed to inner_text. Using 'text_contents' pulls down all the values, not just the single selected setting.
            log.entry(text, 'DEBUG')
            result = None
            for x in range(len(text)):
                if text[x] == search_string:
                    log.entry(f'{text[x]}, {text[x+1]}', 'DEBUG')
                    result = text[x+1]
            if control_num == '3.1.3.5.4':  # This control has a period at the end for no reason and it's ugly. Thanks Google
                if text[-2] == '.':
                    text = text.replace('.', '')
            if not result:
                results[index] = [control_num, 'FAILED -> MANUALLY VALIDATE', False]
            else:
                results[index] = [control_num, prefix + result, False]
        except pwto:
            log.entry(f"  [-] Timeout: {control_num} -> {url}" , "WARNING")
            results[index] = [control_num, 'FAILED -> MANUALLY VALIDATE', False]
        index+=1 
    # return results

    # --- Screenshots ---
    log.entry('[*] Fetching control 4.2.3.1', 'OUT')
    page.goto('https://admin.google.com/ac/dp/rules/')
    time.sleep(5)
    page.screenshot(path=os.path.join(screenshot_path, "4.2.3.1.png"), full_page=True)
    if os.path.isfile(os.path.join(os.path.join(screenshot_path, "4.2.3.1.png"))):
        log.entry('  [*] Screenshot successful', 'OUT')
    else:
        log.entry("Screenshot unsucessful. Collect manually -> https://admin.google.com/ac/dp/rules/", "ERROR")
    results[index] = ['4.2.3.1', 'MANUALLY VALIDATE BY SCREENSHOT AND CHANGE', False]
    index+=1
    
    # --- End Screenshots ---

    # 1.2.1.1
    try:
        log.entry('[*] Fetching control 1.2.1.1', 'OUT')
        page.goto("https://admin.google.com/ac/managedsettings/986128716205/sharing")
        form = page.get_by_label("External Directory sharing", exact=True)
        form.wait_for()
        log.entry(form.inner_text(), 'DEBUG')
        form = form.inner_text().split('\n')
        for c in range(len(form)):
            if form[c] == 'External Directory sharing':
                msg = form[c+1]
                break
        results[index] = ['1.2.1.1', 'External Directory sharing is set to: '+msg, False]
    except pwto:
        log.entry('  [-] Timeout 1.2.1.1 -> https://admin.google.com/ac/managedsettings/986128716205/sharing', "WARNING")
        results[index] = ['1.2.1.1', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1

    # 1.1.1-1.1.2
    try:
        log.entry("[*] Fetching control 1.1.1", 'OUT')
        page.goto('https://admin.google.com/ac/users')
        filter = page.get_by_label('Filter bar for users list')
        filter.wait_for()
        filter.click()
        filter = page.get_by_label('Admin role')
        filter.wait_for()
        filter.click()
        filter = page.get_by_label('Super admin')
        filter.wait_for()
        filter.click()
        filter = page.get_by_role('button').filter(has_text='Apply').click()
        time.sleep(5)        
        rows = page.query_selector_all('[role="row"]')
        log.entry(f'Number of rows: {len(rows)}', "DEBUG")
        results[index] = ['1.1.1', "Number of Super Admins: " + str(len(rows)-1), False]
        log.entry("[*] Fetching control 1.1.2", 'OUT')
        results[index+1] = ['1.1.2', "Number of Super Admins: " + str(len(rows)-1), False]
    except pwto:
        log.entry('  [-] Timeout 1.1.1-1.1.2 -> https://admin.google.com/ac/users', "WARNING")
        results[index] = ['1.1.1', 'FAILED -> MANUALLY VALIDATE', False]
        results[index+1] = ['1.1.2', 'FAILED -> MANUALLY VALIDATE', False]
    index+=2

    try:
        log.entry('[*] Fetching control 3.1.4.1.1', 'OUT')
        page.goto('https://admin.google.com/ac/managedsettings/216932279217/filesharingsettings?hl=en')
        form = page.get_by_role('form')
        form.wait_for()
        text = page.get_by_role('form').inner_text().split('\n')
        log.entry(text, 'DEBUG')
        for x in range(len(text)):
            if text[x] == 'External filesharing':
                msg = text[x+2]
                break
        log.entry(msg, 'DEBUG')
        results[index] = ['3.1.4.1.1', 'External filesharing is set to: ' + msg, False]
    except pwto:
        log.entry('  [-] Timeout 3.1.4.1.1 -> https://admin.google.com/ac/managedsettings/216932279217/filesharingsettings?hl=en', "WARNING")
        results[index] = ['3.1.4.1.1', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1

    try:
        log.entry('[*] Fetching control 4.1.5.1', 'OUT')
        page.goto('https://admin.google.com/ac/security/passwordmanagement?journey=35')
        strong = page.get_by_label('Enforce strong password')
        min = page.get_by_label('Minimum Length')
        next_signin = page.get_by_label('Enforce password policy at next sign-in')
        allow_reuse = page.get_by_label('Allow password reuse')
        expiration = page.get_by_role('option', name='Never expires')
        expiration1 = page.get_by_role('option', name='30 days')
        expiration2 = page.get_by_role('option', name='60 days')
        expiration3 = page.get_by_role('option', name='90 days')
        expiration4 = page.get_by_role('option', name='180 days')
        expiration5 = page.get_by_role('option', name='365 days')
        min.wait_for()
        for exp in [expiration, expiration1, expiration2, expiration3, expiration4, expiration5]:
            if exp.is_visible():
                set_exp = exp.text_content()
        results[index] = ['4.1.5.1', f'\nEnforce strong passwords is set to: {strong.is_checked()}\nMinimum length is set to: {min.get_attribute("value")}\nEnforce password policy at next sign-in is set to: {next_signin.is_checked()}\nAllow password reuse is set to: {allow_reuse.is_checked()}\nPassword reset frequency is set to: {set_exp}', False]
    except pwto:
        log.entry('  [-] Timeout 4.1.5.1 -> https://admin.google.com/ac/security/passwordmanagement?journey=35', "WARNING")
        results[index] = ['4.1.5.1', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1

    try:
        log.entry('[*] Fetching control 4.2.4.1', 'OUT')
        page.goto('https://admin.google.com/u/0/ac/managedsettings/352555445522/sessionmanagementsettings')
        form = page.get_by_role('form')
        form.wait_for()
        drop = page.query_selector_all('[role="combobox"]')
        for elem in drop:
            if elem.inner_text():
                duration = elem.inner_text()
        log.entry(duration, 'DEBUG')
        results[index] = ['4.2.4.1', f'Web session duration is set to: {duration}', False]
    except pwto:
        log.entry('  [-] Timeout 4.2.4.1 -> https://admin.google.com/u/0/ac/managedsettings/352555445522/sessionmanagementsettings', "WARNING")
        results[index] = ['4.2.4.1', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1

    try:   
        # 3.1.2.1.1.1
        log.entry("[*] Fetching control 3.1.2.1.1.1", 'OUT')
        page.goto("https://admin.google.com/ac/managedsettings/55656082996/sharing?hl=en")
        form = page.get_by_label('Sharing options', exact=True)
        form.wait_for()
        text = form.inner_text().split('\n')
        log.entry(text, 'DEBUG')
        sharing = None
        for x in range(len(text)):
            if text[x] == f'Sharing outside of {org}':
                log.entry(f'{text[x]}, {text[x+3]}', 'DEBUG')
                sharing = text[x+3]
        if sharing[:2] == 'ON':
            form.click()
            check = page.get_by_label(f'Warn when files owned by users or shared drives in {org} are shared outside of {org}')
            check.wait_for()
            results[index] = ["3.1.2.1.1.1", f"Files can be shared outside of the domain: ON\nWarn when files are shared outside of the domain: {check.is_checked()}", False]
        else:
            results[index] = ["3.1.2.1.1.1", f"Files can be shared outside of the domain is set to: {sharing}", False]
    except pwto:
        log.entry('  [-] Timeout 3.1.2.1.1.1 -> https://admin.google.com/ac/managedsettings/55656082996/sharing?hl=en', "WARNING")
        results[index] = ['3.1.2.1.1.1', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1
    
    try:
        log.entry('[*] Fetching control 3.1.2.1.1.2')
        if sharing[:2] == 'ON':
            check = page.get_by_label(f'When sharing outside of {org} is allowed, users in {org} can make files and published web content visible to anyone with the link')
            check.wait_for()
            log.entry(f'check: {check.is_checked()}', 'DEBUG')
            if check.is_checked():
                check = 'ON'
            else:
                check = 'OFF'
            results[index] = ['3.1.2.1.1.2', f'Users can make files and published web content visible to anyone with the link set to: {check}', False]
        else:
            results[index] = ["3.1.2.1.1.2", f"Files can be shared outside of the domain is set to: {sharing}", False]
    except pwto:
        log.entry('  [-] Timeout 3.1.2.1.1.2 -> https://admin.google.com/ac/managedsettings/55656082996/sharing?hl=en', "WARNING")
        results[index] = ['3.1.2.1.1.2', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1 

    try:
        # 3.1.3.2.1
        log.entry("[*] Fetching control 3.1.3.2.1", 'OUT')
        page.goto("https://admin.google.com/ac/apps/gmail/authenticateemail?hl=en")
        domain = None
        try:
            # If there is more than one domain, must check manually if each domain is mail-enabled, and if so if DKIM record exists
            page.get_by_role('option').nth(1).text_content(timeout=5000)
            results[index] = ['3.1.3.2.1', 'MORE THAN ONE DOMAIN - MANUALLY VALIDATE EACH DOMAIN WITH DIG', False]
        except pwto:
            domain = page.get_by_role('option').first
            domain.wait_for()
            domain = domain.text_content()
            text = page.get_by_role('form')
            text.wait_for()
            text = text.inner_text().split('\n')
            log.entry(text, 'DEBUG')
            msg = None
            for elem in text:
                if elem[:7] == 'Status:':
                    msg = elem
            if msg:
                results[index] = ['3.1.3.2.1', find_keyword(msg, 'Status: '), False]
            else:
                results[index] = ['3.1.3.2.1', 'FAILED -> MANUALLY VALIDATE', False]
    except pwto:
        log.entry('  [-] Timeout: 3.1.3.2.1 -> https://admin.google.com/ac/apps/gmail/authenticateemail?hl=en', 'WARNING')
        results[index] = ['3.1.3.2.1', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1
    
    # 3.1.3.2.2 SPF
    log.entry(f"[*] Fetching 3.1.3.2.2", "OUT")
    if not domain:
        # If there is more than one domain, must check manually if each domain is mail-enabled, and if so if DKIM record exists
        results[index] = ['3.1.3.2.2', 'MORE THAN ONE DOMAIN - MANUALLY VALIDATE -> https://admin.google.com/ac/apps/gmail/authenticateemail?hl=en', False]
    else:
        log.entry(f"[*] Testing domain {domain} for SPF record", 'OUT')
        try:
            test_spf = resolve(domain , 'TXT')
            found = False
            for dns_data in test_spf:
                if 'spf1' in str(dns_data):
                    log.entry("    [+] SPF record found", 'OUT')
                    log.entry("DNS data: " + str(dns_data), "DEBUG")
                    results[index] = ["3.1.3.2.2", "SPF record found", False]
                    found = True
            if not found:
                log.entry("    [-] SPF record not found", 'OUT')
                results[index] = ["3.1.3.2.2", "No SPF record location for " + domain, False]
        except DNSException as e:
            log.entry(f'    [-] DNS error: {e}', 'WARNING')
            results[index] = ["3.1.3.2.2", "Nonexistent domain: " + domain, False]
    index+=1

    # 3.1.3.2.3 DMARC
    log.entry(f"[*] Fetching 3.1.3.2.3", 'OUT')
    if not domain:
        results[index] = ["3.1.3.2.3", "MULTIPLE DOMAINS -> VALIDATE EACH MANUALLY WITH DIG", False]
    else:
        log.entry(f"[*] Testing domain {domain} for DMARC record", 'OUT')
        try:
            test_dmarc = resolve('_dmarc.' + domain , 'TXT')
            found = False
            for dns_data in test_dmarc:
                if 'dmarc' in str(dns_data):
                    log.entry("    [+] DMARC record found: " + str(dns_data), 'OUT')
                    results[index] = ["3.1.3.2.3", "DMARC record found: " + str(dns_data), False]
                    found = True
            if not found:
                log.entry("    [-] DMARC record not found for " + domain, 'OUT')
                results[index] = ["3.1.3.2.3", "No DMARC record location for "+domain, False]
        except DNSException as e:
            log.entry("  [-] DNS Error: " + str(e), "WARNING")
            results[index] = ["3.1.3.2.3", "Nonexistent domain: " + domain, False]
    index+=1

    try:    
        # 3.1.3.4.1.1 - 3.1.3.4.1.3
        log.entry("[*] Fetching control 3.1.3.4.1.1", 'OUT')
        page.goto("https://admin.google.com/ac/apps/gmail/safety")
        text = page.get_by_label('Attachments', exact=True)
        text.wait_for()
        text = text.inner_text().split('\n')
        log.entry(text, 'DEBUG')
        if "Protect against encrypted attachments from untrusted senders: ON" in text:
            results[index] = ["3.1.3.4.1.1", 'Protect against encrypted attachments from untrusted senders: ON', False]
        elif "Protect against encrypted attachments from untrusted senders: OFF" in text:
            results[index] = ["3.1.3.4.1.1", 'Protect against encrypted attachments from untrusted senders: OFF', False]
        else: 
            results[index] = ["3.1.3.4.1.1", 'FAILED -> MANUALLY VALIDATE', False]

        log.entry("[*] Fetching control 3.1.3.4.1.2", 'OUT')
        if "Protect against attachments with scripts from untrusted senders: ON" in text:
            results[index+1] = ["3.1.3.4.1.2", 'Protect against attachments with scripts from untrusted senders: ON', False]
        elif "Protect against attachments with scripts from untrusted senders: OFF" in text:
            results[index+1] = ["3.1.3.4.1.2", 'Protect against attachments with scripts from untrusted senders: OFF', False]
        else: 
            results[index+1] = ["3.1.3.4.1.2", 'FAILED -> MANUALLY VALIDATE', False]

        log.entry("[*] Fetching control 3.1.3.4.1.3", 'OUT')
        if "Protect against anomalous attachment types in emails: ON" in text:
            results[index+2] = ["3.1.3.4.1.3", 'Protect against anomalous attachment types in emails: ON', False]
        elif "Protect against anomalous attachment types in emails: OFF" in text:
            results[index+2] = ["3.1.3.4.1.3", 'Protect against anomalous attachment types in emails: OFF', False]
        else: 
            results[index+2] = ["3.1.3.4.1.3", 'FAILED -> MANUALLY VALIDATE', False]
    except pwto:
        log.entry('  [-] Timeout 3.1.3.4.1.1 -> https://admin.google.com/ac/apps/gmail/safety', "DEBUG")
        log.entry('  [-] Timeout 3.1.3.4.1.2 -> https://admin.google.com/ac/apps/gmail/safety', "DEBUG")
        log.entry('  [-] Timeout 3.1.3.4.1.3 -> https://admin.google.com/ac/apps/gmail/safety', "DEBUG")
        results[index] = ['3.1.3.4.1.1', 'FAILED -> MANUALLY VALIDATE', False]
        results[index+1] = ['3.1.3.4.1.2', 'FAILED -> MANUALLY VALIDATE', False]
        results[index+2] = ['3.1.3.4.1.3', 'FAILED -> MANUALLY VALIDATE', False]
    index+=3
    
    try:
        # 3.1.3.4.2.1 - 3.1.3.4.2.3
        log.entry("[*] Fetching control 3.1.3.4.2.1", 'OUT')
        text = page.get_by_label('Links and external images', exact=True)
        text.wait_for()
        text = text.inner_text().split('\n')
        log.entry(text, 'DEBUG')
        if "Identify links behind shortened URLs: ON" in text:
            results[index] = ["3.1.3.4.2.1", 'Identify links behind shortened URLs: ON', False]
        elif "Identify links behind shortened URLs: OFF" in text:
            results[index] = ["3.1.3.4.2.1", 'Identify links behind shortened URLs: ON', False]
        else: 
            results[index] = ["3.1.3.4.2.1", 'FAILED -> MANUALLY VALIDATE', False]
        log.entry("[*] Fetching control 3.1.3.4.2.2", "OUT")
        if "Scan linked images: ON" in text:
            results[index+1] = ["3.1.3.4.2.2", "Scan linked images: ON", False]
        elif "Scan linked images: OFF" in text:
            results[index+1] = ["3.1.3.4.2.2", "Scan linked images: OFF", False]
        else: 
            results[index+1] = ["3.1.3.4.2.2", "FAILED -> MANUALLY VALIDATE", False]
        log.entry("[*] Fetching control 3.1.3.4.2.3", 'OUT')
        if "Show warning prompt for any click on links to untrusted domains: ON" in text:
            results[index+2] = ["3.1.3.4.2.3", 'Show warning prompt for any click on links to untrusted domains: ON', False]
        elif "Show warning prompt for any click on links to untrusted domains: OFF" in text:
            results[index+2] = ["3.1.3.4.2.3", 'Show warning prompt for any click on links to untrusted domains: OFF', False]
        else: 
            results[index+2] = ["3.1.3.4.2.3", 'FAILED -> MANUALLY VALIDATE', False]
    except pwto:
        log.entry('  [-] Timeout 3.1.3.4.2.1 -> https://admin.google.com/ac/apps/gmail/safety', "WARNING")
        log.entry('  [-] Timeout 3.1.3.4.2.2 -> https://admin.google.com/ac/apps/gmail/safety', "WARNING")
        log.entry('  [-] Timeout 3.1.3.4.2.3 -> https://admin.google.com/ac/apps/gmail/safety', "WARNING")
        results[index] = ['3.1.3.4.2.1', 'FAILED -> MANUALLY VALIDATE', False]
        results[index+1] = ['3.1.3.4.2.2', 'FAILED -> MANUALLY VALIDATE', False]
        results[index+2] = ['3.1.3.4.2.3', 'FAILED -> MANUALLY VALIDATE', False]
    index+=3

    try:
        # 3.1.3.4.3.1 - 3.1.3.4.3.5
        log.entry("[*] Fetching control 3.1.3.4.3.1","OUT")
        form = page.get_by_label('Spoofing and authentication', exact=True)
        form.wait_for()
        text = form.inner_text().split('\n')
        log.entry(text, 'DEBUG')
        form.click()
        if "Protect against domain spoofing based on similar domain names: ON" in text:
            try:
                option = find_option(page)
                results[index] = ["3.1.3.4.3.1", f'Protect against domain spoofing based on similar domain names: ON and Action is set to: {option}', False]
            except ValueError:
                results[index] = ["3.1.3.4.3.1", 'FAILED -> MANUALLY VALIDATE', False]
        elif 'Protect against domain spoofing based on similar domain names: OFF' in text:
            results[index] = ["3.1.3.4.3.1", 'Protect against domain spoofing based on similar domain names: OFF', False]
        else: 
            results[index] = ["3.1.3.4.3.1", 'FAILED -> MANUALLY VALIDATE', False]

        log.entry("[*] Fetching control 3.1.3.4.3.2", 'OUT')
        if 'Protect against spoofing of employee names: ON' in text:
            try:
                option = find_option(page)
                results[index+1] = ["3.1.3.4.3.2", 'Protect against spoofing of employee names: ON and Action is set to: ' + option, False]
            except ValueError:
                results[index+1] = ["3.1.3.4.3.2", 'FAILED -> MANUALLY VALIDATE' + option, False]
        elif 'Protect against spoofing of employee names: OFF' in text:
            results[index+1] = ["3.1.3.4.3.2", 'Protect against spoofing of employee names: OFF', False]
        else: 
            results[index+1] = ["3.1.3.4.3.2", 'FAILED -> MANUALLY VALIDATE', False]
        
        log.entry("[*] Fetching control 3.1.3.4.3.3", 'OUT')
        if 'Protect against inbound emails spoofing your domain: ON' in text:
            try:
                option = find_option(page)
                results[index+2] = ["3.1.3.4.3.3", 'Protect against inbound emails spoofing your domain: ON and action is set to: ' + option, False]
            except ValueError:
                results[index+2] = ["3.1.3.4.3.3", 'FAILED -> MANUALLY VALIDATE' + option, False]
        elif 'Protect against inbound emails spoofing your domain: OFF' in text:
            results[index+2] = ["3.1.3.4.3.3", 'Protect against inbound emails spoofing your domain: OFF', False]
        else: 
            results[index+2] = ["3.1.3.4.3.3", 'FAILED -> MANUALLY VALIDATE', False]

        log.entry("[*] Fetching control 3.1.3.4.3.4", 'OUT')
        if 'Protect against any unauthenticated emails: ON' in text:
            results[index+3] = ["3.1.3.4.3.4", 'Protect against any unauthenticated emails: ON', False]
        elif 'Protect against any unauthenticated emails: OFF' in text:
            results[index+3] = ["3.1.3.4.3.4", 'Protect against any unauthenticated emails: OFF', False]
        else: 
            results[index+3] = ["3.1.3.4.3.4", 'FAILED -> MANUALLY VALIDATE', False]

        log.entry("[*] Fetching control 3.1.3.4.3.5", 'OUT')
        if 'Protect your Groups from inbound emails spoofing your domain: ON' in text:
            try:
                option = find_option(page)
                results[index+4] = ["3.1.3.4.3.5", 'Protect your Groups from inbound emails spoofing your domain: ON and Action is set to: ' + option, False]
            except ValueError:
                results[index+4] = ["3.1.3.4.3.5", 'FAILED -> MANUALLY VALIDATE', False]
        elif 'Protect your Groups from inbound emails spoofing your domain: OFF' in text:
            results[index+4] = ["3.1.3.4.3.5", 'Protect your Groups from inbound emails spoofing your domain: OFF', False]
        else:
            results[index+4] = ["3.1.3.4.3.5", 'FAILED -> MANUALLY VALIDATE', False]
    except pwto:
        log.entry('  [-] Timeout 3.1.3.4.3.1 -> https://admin.google.com/ac/apps/gmail/safety', "WARNING")
        log.entry('  [-] Timeout 3.1.3.4.3.2 -> https://admin.google.com/ac/apps/gmail/safety', "WARNING")
        log.entry('  [-] Timeout 3.1.3.4.3.3 -> https://admin.google.com/ac/apps/gmail/safety', "WARNING")
        log.entry('  [-] Timeout 3.1.3.4.3.4 -> https://admin.google.com/ac/apps/gmail/safety', "WARNING")
        log.entry('  [-] Timeout 3.1.3.4.3.5 -> https://admin.google.com/ac/apps/gmail/safety', "WARNING")
        results[index] = ['3.1.3.4.3.1', 'FAILED -> MANUALLY VALIDATE', False]
        results[index+1] = ['3.1.3.4.3.2', 'FAILED -> MANUALLY VALIDATE', False]
        results[index+2] = ['3.1.3.4.3.3', 'FAILED -> MANUALLY VALIDATE', False]
        results[index+3] = ['3.1.3.4.3.4', 'FAILED -> MANUALLY VALIDATE', False]
        results[index+4] = ['3.1.3.4.3.5', 'FAILED -> MANUALLY VALIDATE', False]
    index+=5
    
    try:
        # 3.1.3.5.2
        log.entry("[*] Fetching control 3.1.3.5.2", 'OUT')
        page.goto("https://admin.google.com/ac/apps/gmail/enduseraccess")
        text = page.get_by_label("Automatic forwarding", exact=True)
        text.wait_for()
        log.entry(text.inner_text(), 'DEBUG')
        if 'Allow users to automatically forward incoming email to another address: OFF' in text.inner_text():
            results[index] = ["3.1.3.5.2", "Allow users to automatically forward incoming email to another address: OFF", False]
        elif 'Allow users to automatically forward incoming email to another address: ON' in text.inner_text():
            results[index] = ["3.1.3.5.2", "Allow users to automatically forward incoming email to another address: ON", False]
        else:
            results[index] = ["3.1.3.5.2", "FAILED -> MANUALLY VALIDATE", False]
    except pwto:
        log.entry('  [-] Timeout 3.1.3.4.5.2 -> https://admin.google.com/ac/apps/gmail/enduseraccess', "WARNING")
        results[index] = ['3.1.3.4.5.2', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1
    
    try:
        log.entry('[*] Fetching control 3.1.3.6.2', 'OUT')
        page.goto('https://admin.google.com/ac/apps/gmail/spam?hl=en')
        btn = page.get_by_label("Spam", exact=True).get_by_role("button", name="Configure")
        btn.wait_for()
        btn.click()
        checked = page.locator("label").filter(has_text="Bypass spam filters for internal senders.").get_by_role("checkbox")
        checked.wait_for()
        log.entry(checked.is_checked(), 'DEBUG')
        if checked.is_checked():
            results[index] = ['3.1.3.6.2', 'Bypass spam filters for messages received from internal senders is: ON', False]
        else:
            results[index] = ['3.1.3.6.2', 'Bypass spam filters for messages received from internal senders is: OFF', False]
    except pwto:
        log.entry('  [-] Timeout 3.1.3.6.2 -> https://admin.google.com/ac/apps/gmail/spam?hl=en', "WARNING")
        results[index] = ['3.1.3.6.2', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1

    try:    
        log.entry("[*] Fetching control 3.1.4.2.2", 'OUT')
        page.goto("https://admin.google.com/ac/managedsettings/216932279217/externalchatsettings?hl=en")
        radio_on = page.get_by_label('ON', exact=True)
        radio_off = page.get_by_label('OFF', exact=True)
        checked_warn = page.get_by_role('checkbox')
        radio_on.wait_for()
        for radio in [radio_on, radio_off]:
            if radio.is_checked():
                msg = radio.get_attribute('aria-label')
        results[index] = ['3.1.4.2.2', f'Allow users to chat externally is set to: {msg}\nRestrict external chats to allowlisted domains: {checked_warn.is_checked()}', False]
    except pwto:
        log.entry('  [-] Timeout 3.1.4.2.2 -> https://admin.google.com/ac/managedsettings/216932279217/externalchatsettings?hl=en', "WARNING")
        results[index] = ['3.1.4.2.2', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1

    try:
        log.entry("[*] Fetching control 3.1.4.3.1", 'OUT')
        page.goto("https://admin.google.com/ac/managedsettings/216932279217/guestroomsettings?hl=en")
        radio_on = page.get_by_label('ON', exact=True)
        radio_off = page.get_by_label('OFF', exact=True)
        checked_warn = page.get_by_role('checkbox')
        radio_on.wait_for()
        for radio in [radio_on, radio_off]:
            if radio.is_checked():
                msg = radio.get_attribute('aria-label')
        results[index] = ['3.1.4.3.1', f'Users can create and join spaces with people outside their organization: {msg}\nOnly allow users to add people from allowlisted domains: {checked_warn.is_checked()}', False]
    except pwto:
        log.entry('  [-] Timeout 3.1.4.3.1 -> https://admin.google.com/ac/managedsettings/216932279217/guestroomsettings?hl=en', "WARNING")
        results[index] = ['3.1.4.3.1', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1

    try:
        log.entry('[*] Fetching control 3.1.4.4.1', 'OUT')
        page.goto('https://admin.google.com/ac/managedsettings/216932279217?hl=en')
        text = page.get_by_label('Chat apps', exact=True).text_content()
        allow_install = find_keyword(text, 'Allow users to install Chat apps: ').split(',')[0]
        log.entry(text, 'DEBUG')
        results[index] = ['3.1.4.4.1', "Allow users to install Chat apps: " + allow_install, False]
    except pwto:
        log.entry('  [-] Timeout 3.1.4.4.1 -> https://admin.google.com/ac/managedsettings/216932279217?hl=en', "WARNING")
        results[index] = ['3.1.4.4.1', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1

    try:
        log.entry('[*] Fetching control 3.1.4.4.2', 'OUT')
        allow_hooks = find_keyword(text, 'Allow users to add and use incoming webhooks: ')
        log.entry(allow_hooks, 'DEBUG')
        if allow_hooks[:2] == 'ON':
            results[index] = ['3.1.4.4.2', "Allow users to add and use incoming webhooks: ON", False]
        elif allow_hooks[:3] == 'OFF':
            results[index] = ['3.1.4.4.2', "Allow users to add and use incoming webhooks: OFF", False]
        else:
            results[index] = ['3.1.4.4.2', "FAILED -> MANUALLY VALIDATE", False]
    except pwto:
        log.entry('  [-] Timeout 3.1.4.4.2 -> https://admin.google.com/ac/managedsettings/216932279217?hl=en', "WARNING")
        results[index] = ['3.1.4.4.2', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1 

    try:
        log.entry('[*] Fetching control 3.1.6.1', 'OUT')
        page.goto('https://admin.google.com/ac/managedsettings/864450622151?hl=en')
        text = page.get_by_label("Sharing settings", exact=True)
        text.wait_for()
        text = find_keyword(text.text_content(), 'Accessing groups from outside this organization: ').split(',')[0]
        log.entry(text, 'DEBUG')
        results[index] = ['3.1.6.1', "Accessing groups from outside this organization is set to: " + text, False]
    except pwto:
        log.entry("Timeout: 3.1.6.1 -> https://admin.google.com/ac/managedsettings/864450622151?hl=en" , "WARNING")
        results[index] = ['3.1.6.1', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1

    try:
        log.entry('[*] Fetching control 3.1.6.2', 'OUT')
        msg = None
        page.goto('https://admin.google.com/ac/managedsettings/864450622151/GROUPS_SHARING_SETTINGS_TAB?hl=en')
        radio = page.get_by_label('Only organization admins can create groups')
        radio1 = page.get_by_label('Anyone in the organization can create groups')
        radio2 = page.get_by_label('Anyone on the internet can create groups')
        external_check = page.get_by_label('Group owners can allow external members')
        email_check = page.get_by_label('Group owners can allow incoming email')
        radio.wait_for()
        for r in [radio, radio1, radio2]:
            if r.is_checked():
                msg = r.get_attribute('aria-label')
        if not msg:
            raise IndexError
        results[index] = ['3.1.6.2', f'Creating Groups is set to: {msg}\nGroup owners can allow external members: {external_check.is_checked()}\nGroup owners can allow incoming email from outside the organization: {email_check.is_checked()}', False]
    except pwto:
        log.entry("Timeout: 3.1.6.2 -> https://admin.google.com/ac/managedsettings/864450622151/GROUPS_SHARING_SETTINGS_TAB?hl=en" , "WARNING")
        results[index] = ['3.1.6.2', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1

    try:
        msg = None
        log.entry('[*] Fetching control 3.1.6.3', 'OUT')
        radio = [page.get_by_label("Owners only", exact=True), "Owners only"]
        radio1 = [page.get_by_label("Owners and managers", exact=True), "Owners and managers"]
        radio2 = [page.get_by_label("All group members", exact=True), "All group members"]
        radio3 = [page.get_by_label("All organization users", exact=True), "All organization users"]
        radio4 = [page.get_by_label("Anyone on the internet", exact=True), "Anyone on the internet"]
        radio4[0].wait_for()
        for r in [radio, radio1, radio2, radio3, radio4]:
            if r[0].is_checked():
                msg = r[1]
                log.entry(f'radio: {r[0].is_checked()}, msg: {msg}', 'DEBUG')
        if not msg:
            raise IndexError
        results[index] = ['3.1.6.3', 'Default for permission to view conversations is set to: ' + msg, False]
    except pwto:
        log.entry('  [-] Timeout 3.1.6.3 -> https://admin.google.com/ac/managedsettings/864450622151/GROUPS_SHARING_SETTINGS_TAB?hl=en', "WARNING")
        results[index] = ['3.1.6.3', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1

    try:
        log.entry('[*] Fetching control 3.1.7.1', 'OUT')
        page.goto('https://admin.google.com/ac/settings/serviceonoff?iid=112&aid=142495531730')
        radio_on = page.get_by_label('ON for everyone')
        radio_off = page.get_by_label('OFF for everyone')
        radio_on.wait_for()
        log.entry(f'radio_on: {radio_on.is_checked()}, radio_off: {radio_off.is_checked()}', 'DEBUG')
        if radio_on.is_checked():
            results[index] = ['3.1.7.1', 'Service status for Google Sites is set to: ON', False]
        elif radio_off.is_checked():
            results[index] = ['3.1.7.1', 'Service status for Google Sites is set to: OFF', False]
        else:
            results[index] = ['3.1.7.1', 'FAILED -> MANUALLY VALIDATE', False]
    except pwto:
        log.entry("Timeout: 3.1.7.1 -> https://admin.google.com/u/0/ac/managedsettings/142495531730" , "WARNING")
        results[index] = ['3.1.7.1', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1

    try:
        log.entry('[*] Fetching control 3.1.8.1', 'OUT')
        page.goto('https://admin.google.com/ac/appsettings/781496888058')
        text = page.get_by_label('Service status', exact=True)
        text.wait_for()
        text = find_keyword(text.text_content(), 'Service status')
        text = text.replace('\ue5cf', '')
        text = text.replace (' for everyone', '')
        log.entry('Found text: '+ text, 'DEBUG')
        results[index] = ['3.1.8.1', 'Service status for Google Groups is set to: ' + text, False]
    except pwto:
        log.entry("Timeout: 3.1.8.1 -> https://admin.google.com/ac/appsettings/781496888058" , "WARNING")
        results[index] = ['3.1.8.1', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1

    try:
        log.entry('[*] Fetching control 3.1.9.1.1', 'OUT')
        page.goto('https://admin.google.com/ac/apps/gmail/marketplace/allowlistaccess')
        radio = [page.get_by_label("Allow users to install and run any app from the Marketplace"), "Allow users to install and run any app from the Marketplace"]
        radio1 = [page.get_by_label("Allow users to install and run allowlisted apps from the Marketplace"), "Allow users to install and run allowlisted apps from the Marketplace"]
        radio2 = [page.get_by_label("Don't allow users to install and run apps from the Market"), "Don't allow users to install and run apps from the Market"]
        radio[0].wait_for()

        for r in [radio, radio1, radio2]:
            if r[0].is_checked():
                msg = r[1]
        results[index] = ['3.1.9.1.1', msg, False]
    except pwto:
        log.entry("Timeout: 3.1.9.1.1 -> https://admin.google.com/ac/apps/gmail/marketplace/allowlistaccess" , "WARNING")
        results[index] = ['3.1.9.1.1', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1

    try: 
        log.entry('[*] Fetching control 4.2.1.3', 'OUT')
        page.goto('https://admin.google.com/ac/owl/settings')
        text = page.get_by_role('form').nth(2)
        text.wait_for()
        text = text.inner_text().split('\n')[1]
        log.entry(f'Found text: {text}', 'DEBUG')
        results[index] = ['4.2.1.3', text, False]
    except pwto:
        log.entry("Timeout: 4.2.1.3 -> https://admin.google.com/ac/owl/settings" , "WARNING")
        results[index] = ['4.2.1.3', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1

    try: 
        log.entry('[*] Fetching control 4.2.6.1', 'OUT')
        page.goto('https://admin.google.com/ac/security/lsa?journey=47')
        radio = page.locator("li").filter(has_text="Disable access to less secure apps (Recommended)").get_by_role("radio")
        radio.wait_for()
        log.entry('Found radio', 'DEBUG')
        if radio.is_checked():
            results[index] = ['4.2.6.1', 'Disable access to less secure apps is selected', False]
        else:
            results[index] = ['4.2.6.1', 'Allow users to manage their access to less secure apps is selected', False]
    except pwto:
        log.entry("Timeout: 4.2.6.1 -> https://admin.google.com/ac/security/lsa?journey=47" , "WARNING")
        results[index] = ['4.2.6.1', 'FAILED -> MANUALLY VALIDATE', False]
    index+=1 
    
    # Controls 6.1-6.8
    urls = ['https://admin.google.com/ac/ax/details?alertType=27', 'https://admin.google.com/ac/ax/details?alertType=13', 'https://admin.google.com/ac/ax/details?alertType=5', 'https://admin.google.com/ac/ax/details?alertType=23', 'https://admin.google.com/ac/ax/details?alertType=4', 'https://admin.google.com/ac/ax/details?alertType=3','https://admin.google.com/ac/ax/details?alertType=6', 'https://admin.google.com/ac/ax/details?alertType=48']
    c = 1
    url = ''
    for url in urls:
        try: 
            log.entry('[*] Fetching control 6.' + str(c), 'OUT')
            if c == 8:
                pass
            page.goto(url)
            actions = page.get_by_role('main')
            actions.wait_for()
            time.sleep(2)
            actions = actions.text_content()
            actions = find_keyword(actions, 'Actions')
            log.entry(f'Found actions: {actions}', 'DEBUG')
            alerts = find_keyword(actions, 'Alerts')
            for o in ['On', 'Off']:
                if find_keyword(alerts, o):
                    alerts = o
            severity = find_keyword(actions, 'Severity')
            for sev in ['Low', 'Medium', 'High']:
                if find_keyword(severity, sev):
                    severity = sev
            email = find_keyword(actions, "Email Notifications")
            for o in ['On', 'Off']:
                if find_keyword(email, o):
                    email = o
            recip = find_keyword(actions, "Email notification recipients")
            if not recip:
                recip = 'Email notifications disabled'
            log.entry(str(recip), 'DEBUG')
            results[index] = [f'6.{c}', f'Alerts: {alerts}\nSeverity: {severity}\nEmail Notifications: {email}\nNotification recipients: {recip}', False]
            log.entry(results[index], 'DEBUG')
            actions = None
            alerts = None
            email = None
            severity = None
            recip = None
        except pwto:
            log.entry(f"  [-] Timeout: 6.{c} -> {url}" , "WARNING")
            results[index] = [f'6.{c}', 'FAILED -> MANUALLY VALIDATE', False]
        index+=1 
        c+=1

    # ---- MANUAL CONTROLS ----
    # REDO
    log.entry('[*] Fetching control 4.1.1.1', 'OUT')
    results[index] = ['4.1.1.1', 'MANUALLY VALIDATE -> https://admin.google.com/ac/security/2sv?journey=32', False]
    index+=1
    # REDO
    log.entry('[*] Fetching control 4.1.1.3', 'OUT')
    results[index] = ['4.1.1.3', 'MANUALLY VALIDATE -> https://admin.google.com/ac/security/2sv?journey=32', False]
    index+=1
    
    # Cannot be automated, must be done manually
    log.entry('[*] Fetching control 4.2.2.1', 'OUT')
    results[index] = ['4.2.2.1', 'MANUALLY VALIDATE -> https://admin.google.com/ac/security/context-aware/access-levels', False]
    index+=1


    # Needs to be inspected manually during analysis phase. Indicate after manual investigation whether compliant or not
    log.entry('[*] Fetching control 4.3.1', 'OUT')
    results[index] = ['4.3.1', 'REVIEW AND INTERVIEW CLIENT -> https://admin.google.com/ac/reporting/report/user/accounts', False]
    index+=1

    # Needs to be inspected manually during analysis phase. Indicate after manual investigation whether compliant or not
    log.entry('[*] Fetching control 4.3.2', 'OUT')
    results[index] = ['4.3.2', 'REVIEW AND INTERVIEW CLIENT -> https://admin.google.com/ac/sc/security-health', False]
    index+=1
    
    # Needs to be inspected manually during analysis phase. Indicate after manual investigation whether compliant or not
    log.entry('[*] Fetching control 5.1.1.1', 'OUT')
    results[index] = ['5.1.1.1', 'REVIEW AND INTERVIEW CLIENT -> https://admin.google.com/ac/reporting/report/user/apps_usage', False]
    index+=1

    # Needs to be inspected manually during analysis phase. Indicate after manual investigation whether compliant or not
    log.entry('[*] Fetching control 5.1.1.2', 'OUT')
    results[index] = ['5.1.1.2', 'REVIEW AND INTERVIEW CLIENT -> https://admin.google.com/ac/reporting/report/user/security', False]
    index+=1

    # 3.1.3.3.1
    log.entry("[*] Fetching control 3.1.3.3.1", 'OUT')
    results[index] = ["3.1.3.3.1", "MANUAL CONTROL -> https://admin.google.com/ac/apps/gmail/managequarantine", False]
    index+=1 

    for r in results.values():
        if ':' not in r[1] and r[1][-1] != '.':
            r[1] += '.'
        if ':' in r[1] and r[1][-1] == '.':
            r[1] = r[1][:-1]
    return results

def find_option(page):
    action = page.get_by_role('option', name='Move email to spam').first
    action1 = page.get_by_role('option', name='Keep email in inbox and show warning (default)').first
    action2 = page.get_by_role('option', name='Quarantine').first
    option = None
    for a in [action, action1, action2]:
        if a.is_visible():
            option = a.text_content()
    if not option: raise ValueError
    return option

def text_by_aria(page):
    aria_list = []
    with open('aria-list', 'r') as aria:
        for line in aria:
            aria_list.append(line.strip())

    for item in aria_list:
        log.entry(f'----{item}----', 'DEBUG')
        elements = page.query_selector_all(f'[role="{item}"]')
        for e in elements:
            log.entry('text: ' + e.text_content(), 'DEBUG')
            log.entry('inner: ' + e.inner_text(), 'DEBUG')

def find_keyword(text, keyword):
    index = text.find(keyword)
    if index == -1:
        return None
    return text[index + len(keyword):]

with sync_playwright() as playwright:
    org = input('[?] Enter organization acronym: ')
    results_path = f'./Results/{org}'
    log_path = f"./Logs/{org}"
    screenshot_path = (f'{results_path}/Screenshots')

    if not os.path.isdir('./Results'):
        os.mkdir('./Results')
    if not os.path.isdir(results_path):
        os.mkdir(results_path)
    if not os.path.isdir(log_path):
        os.mkdir(log_path)
    if not os.path.isdir(screenshot_path):
        os.mkdir(screenshot_path)
    log = Log(log_path, uniq=False)    

    results = run(playwright)
    log.entry('Data gathering complete', 'DEBUG')
    results = analyze(results)
    log.entry('Analysis complete', 'DEBUG')
    log.entry('Results: ' + str(results), 'DEBUG')

    # Write raw data to csv and check if file is created
    with open(results_path + '/results.csv', 'w') as out:
        out.write('sep=;\n')
        for result in results.values():
            for x in range(3):
                result[x] = str(result[x])
            result[1] = result[1].replace('\n', '')
            tmp = ';'.join(result)
            out.writelines(tmp + "\n")
    if os.path.exists(results_path + '/results.csv'):
        log.entry('[*] Results logged to results.csv, script complete', 'OUT')
    else:
        log.entry('[!] Something went wrong. Results not logged to results.csv properly', 'WARNING')