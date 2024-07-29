def extract_email_artifacts(vault_id=None, container_id=None, severity=None, run_automation=None, extract_ip=None, extract_uri=None, decode_safelinks=None, extract_domain=None, **kwargs):
    """
    Extracts IP addresses, URIs, domains from an email message and creates related artifacts.
    
    Args:
        vault_id (CEF type: vault id): The ID of the vault containing the email.
        container_id (CEF type: phantom container id): The identifier of the container to which the artifacts will be added.
        severity: The severity level of the new artifact. This parameter is optional and defaults to "Medium". Acceptable values are "High", "Medium", or "Low".
        run_automation:  A boolean value ("true" or "false") indicating whether the new artifact should trigger the execution of any active playbooks associated with the container label. This parameter is optional and defaults to "false".
        extract_ip: A boolean value ("true" or "false") indicating whether to extract IP addresses. This parameter is optional and defaults to "true".
        extract_uri: A boolean value ("true" or "false") indicating whether to extract URIs. This parameter is optional and defaults to "true".
        decode_safelinks: A boolean value ("true" or "false") indicating whether to decode safelinks. This parameter is optional and defaults to "true".
        extract_domain: A boolean value ("true" or "false") indicating whether to extract domains from URIs. This parameter is optional and defaults to "true".
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    from urllib.parse import unquote
    from bs4 import BeautifulSoup
    from email import policy
    from email.parser import BytesParser
    
    URI_REGEX = r'([Hh][Tt][Tt][Pp][Ss]?:\/\/)((?:[:@\.\-_0-9]|[^ -@\[-\`\{-\~\s]|' \
        r'[\[\(][^\s\[\]\(\)]*[\]\)])+)((?:[\/\?]+(?:[^\[\(\{\)\]\}\s]|[\[\(][^\[\]\(\)]*[\]\)])*)*)[\/]?'
    IP_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    IPV6_REGEX = r'\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|' \
        r'(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))' \
        r'|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|' \
        r'(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)' \
        r'(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|' \
        r'(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)' \
        r'(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|' \
        r'(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)' \
        r'(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|' \
        r'(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)' \
        r'(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|' \
        r'(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)' \
        r'(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*'
    
    # Input validation
    if not isinstance(vault_id, str):
        raise TypeError("Expected vault_id to be a string")
    if not isinstance(container_id, int) and container_id is not None:
        raise TypeError("Expected container_id to be an integer")
    if severity is not None and severity not in {"High", "Medium", "Low"}:
        raise ValueError("Expected severity to be 'High', 'Medium', or 'Low'")
    if run_automation is not None and run_automation.lower() not in {"true", "false"}:
        raise ValueError("Expected run_automation to be 'true' or 'false'")
    if extract_ip is not None and extract_ip.lower() not in {"true", "false"}:
        raise ValueError("Expected extract_ip to be 'true' or 'false'")
    if extract_uri is not None and extract_uri.lower() not in {"true", "false"}:
        raise ValueError("Expected extract_uri to be 'true' or 'false'")
    if decode_safelinks is not None and decode_safelinks.lower() not in {"true", "false"}:
        raise ValueError("Expected decode_safelinks to be 'true' or 'false'")
    if extract_domain is not None and extract_domain.lower() not in {"true", "false"}:
        raise ValueError("Expected extract_domain to be 'true' or 'false'")
        
    # Convert boolean-like strings to actual boolean values
    def str_to_bool(value, default=False):
        if isinstance(value, str):
            return value.lower() == 'true'
        return default
    
    run_automation = str_to_bool(run_automation, False)
    extract_ip = str_to_bool(extract_ip, True)
    extract_uri = str_to_bool(extract_uri, True)
    decode_safelinks = str_to_bool(decode_safelinks, True)
    extract_domain = str_to_bool(extract_domain, True)
    
    # Set default value for container_id if not provided
    if container_id is None:
        container_id = int(phantom.get_current_container_id_())

    # Get vault info
    success, message, vault_info = phantom.vault_info(vault_id=vault_id)
    if not success:
        raise RuntimeError("Failed to get vault info: {}".format(message))
        
    vault_info = list(vault_info)[0]
    phantom.debug("vault_info: {}".format(vault_info))

    vault_path = vault_info.get('path')
    phantom.debug("vault_path: {}".format(vault_path))

    if not vault_path:
        raise ValueError("No vault path returned for vault_id: {}, message: {}".format(vault_id, message))
    
    artifacts = {
        'ips': [],
        'uris': [],
        'decoded_safelinks': [],
        'domains': []
    }

    try:
        with open(vault_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        # Extract SMTP sender
        artifacts['smtp_sender'] = msg['from']

        # Extract message content
        text_content = ""
        html_content = ""
        if msg.is_multipart():
            for part in msg.iter_parts():
                if part.get_content_type() == 'text/plain':
                    text_content += part.get_payload(decode=True).decode(part.get_content_charset())
                elif part.get_content_type() == 'text/html':
                    html_content += part.get_payload(decode=True).decode(part.get_content_charset())
        else:
            if msg.get_content_type() == 'text/plain':
                text_content = msg.get_payload(decode=True).decode(msg.get_content_charset())
            elif msg.get_content_type() == 'text/html':
                html_content = msg.get_payload(decode=True).decode(msg.get_content_charset())

        # Extract IPs
        if extract_ip:
            artifacts['ips'] = re.findall(IP_REGEX, text_content) + re.findall(IPV6_REGEX, text_content)

        # Extract URIs
        if extract_uri:
            uris = re.findall(URI_REGEX, text_content)
            artifacts['uris'] = [f"{match[0]}{match[1]}{match[2]}" for match in uris]

        # Decode safelinks
        if decode_safelinks and html_content:
            soup = BeautifulSoup(html_content, 'html.parser')
            for anchor in soup.find_all('a', href=True):
                href = anchor['href']
                if "safelinks.protection.outlook.com" in href:
                    decoded_url = unquote(href.split('url=')[1].split('&')[0])
                    artifacts['decoded_safelinks'].append(decoded_url)
                    if extract_uri:
                        artifacts['uris'].append(decoded_url)

        # Extract domains from URIs
        if extract_domain:
            artifacts['domains'] = list(set(re.findall(r"https?://([^/]+)", " ".join(artifacts['uris']))))

    except Exception as e:
        phantom.error("Error in extract_email_artifacts: {}".format(e))
        raise  # Re-raise the exception after logging it

    # Return a JSON-serializable object
    assert isinstance(artifacts, dict)  # Will raise an exception if the :artifacts: object is not a dict
    assert json.dumps(artifacts)  # Will raise an exception if the :artifacts: object is not JSON-serializable
    return artifacts
