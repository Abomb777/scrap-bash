#!/bin/bash
set +e  # Don't exit on error - continue execution

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
BLUE='\033[0;34m'

LOGIN_EMAIL=""
LOGIN_PASSWD=""
DOMAIN=""
TG_BOT_TOKEN=""
TG_BOT_CHANNEL=""
TG_BOT_CHANNEL_TXT=""
TG_DEBUGER=false

DEBUG_DATA=0
MAX_PAGES_BACK=1
DELAY_SECONDS=1
CATEGORY=1
TEMP_KW_PREFIX=$(date +%Y%m%d)

# Get current directory, fallback to . if pwd fails (can happen when piped)
CURRENT_DIR=$(pwd 2>/dev/null || echo ".")

#check if bsdtar is installed
if ! command -v bsdtar >/dev/null 2>&1; then
    echo -e "\033[0;31mError: bsdtar is not installed. Please install it.\033[0m" >&2
    exit 1
else 
    echo "bsdtar is installed"
fi

# Check if current directory is writable
if [ ! -w "${CURRENT_DIR}" ]; then
    echo -e "\033[0;31mError: Current directory '${CURRENT_DIR}' is not writable. Check permissions.\033[0m" >&2
    exit 1
fi

# Create temp directory
mkdir -p "${CURRENT_DIR}/temp" || {
    echo -e "\033[0;31mError: Failed to create temp directory '${CURRENT_DIR}/temp'. Check permissions.\033[0m" >&2
    exit 1
}
chmod 777 "${CURRENT_DIR}/temp"

# Verify temp directory is writable
if [ ! -w "${CURRENT_DIR}/temp" ]; then
    echo -e "\033[0;31mError: Temp directory '${CURRENT_DIR}/temp' is not writable. Check permissions.\033[0m" >&2
    exit 1
fi

rm -f "${CURRENT_DIR}/temp/page_response_.*.html"
rm -f "${CURRENT_DIR}/temp/page_response_.*.bin"
rm -f "${CURRENT_DIR}/temp/page_response_.*.png"
rm -f "${CURRENT_DIR}/temp/page_response_.*.zip"
rm -f "${CURRENT_DIR}/temp/page_response_.*.txt"


echo "Del protect 5 seconds"
echo "------------------------------------------"
sleep 5


while getopts "c:l:dt:q:x:u:p:w:z:h" opt; do
    case $opt in
        c) CATEGORY=$OPTARG ;;
        l) DOMAIN=$OPTARG ;;
        d) DEBUG_DATA=1 ;;
        t) TG_BOT_TOKEN=$OPTARG ;;
        q) TG_BOT_CHANNEL=$OPTARG ;;
        x) TG_BOT_CHANNEL_TXT=$OPTARG ;;
        u) LOGIN_EMAIL=$OPTARG ;;
        p) LOGIN_PASSWD=$OPTARG ;;
        w) MAX_PAGES_BACK=$OPTARG ;;
        z) TEMP_KW_PREFIX=$(date +$OPTARG) ;;
        h) echo "Usage: $0 -c <category> -l <domain> -d -t <tg_bot_token> -q <tg_bot_channel> -x <tg_bot_channel_txt> -u <login_email> -p <login_password> -w <max_pages_back> -h"; exit 0;;
        *) echo "Invalid option: -$OPTARG" >&2; exit 1;;
    esac
done

TEMP_KW_FILE="${CURRENT_DIR}/temp/keywords_${CATEGORY}_${TEMP_KW_PREFIX}.txt"
if [ -f "$TEMP_KW_FILE" ]; then
    echo "Temp keywords file found: $TEMP_KW_FILE"
    KW_CONTENT=$(cat "$TEMP_KW_FILE")
    if [ -z "$KW_CONTENT" ]; then
        echo "No keywords found in temp keywords file"
    else
        echo "Keywords found in temp keywords file: $KW_CONTENT"
        rm -f "${CURRENT_DIR}/temp/keywords_${CATEGORY}_*.txt"
        echo "$KW_CONTENT" > "$TEMP_KW_FILE"
        echo "Keywords added to temp keywords file: $TEMP_KW_FILE"
    fi
else 
    echo "No keywords found in temp keywords file"
    echo "Creating temp keywords file: $TEMP_KW_FILE"
    touch "$TEMP_KW_FILE" || {
        echo "Error: Failed to create temp keywords file" >&2
        exit 1
    }
    echo "Temp keywords file created: $TEMP_KW_FILE"
    echo "No keywords found in temp keywords file"
fi

if [ -z "$TG_BOT_CHANNEL_TXT" ]; then
    TG_BOT_CHANNEL_TXT="$TG_BOT_CHANNEL"
fi

POSITIONS_FILE="${CURRENT_DIR}/temp/positions_${CATEGORY}.txt"
touch "$POSITIONS_FILE" || {
    echo "Error: Failed to create positions file" >&2
    exit 1
}

if [ "$DEBUG_DATA" -eq 1 ]; then
    echo "Debug data is enabled"
    echo -e "${BLUE}------------------------------------------${NC}"
    echo -e "${BLUE}Category: $CATEGORY${NC}"
    echo -e "${BLUE}Domain: $DOMAIN${NC}"
    echo -e "${BLUE}TG Bot Token: $TG_BOT_TOKEN${NC}"
    echo -e "${BLUE}TG Bot Channel: $TG_BOT_CHANNEL${NC}"
    echo -e "${BLUE}TG Bot Channel TXT: $TG_BOT_CHANNEL_TXT${NC}"
    echo -e "${BLUE}Login Email: $LOGIN_EMAIL${NC}"
    echo -e "${BLUE}Login Password: $LOGIN_PASSWD${NC}"
    echo -e "${BLUE}Max Pages Back: $MAX_PAGES_BACK${NC}"
    echo -e "${BLUE}Temp keywords file: $TEMP_KW_FILE${NC}"
    echo -e "${BLUE}------------------------------------------${NC}"
else
    echo "Debug data is disabled"
fi

echo -e "\033[0;32mLoading...\033[0m";
LINK_URL="https://${DOMAIN}/?adType=${CATEGORY}"
COOKIES=''
IDS_LIST=()
KEYWORDS_LIST=()
ADS_DATA_LIST=()
UNIQUE_KEYWORDS_LIST=()

COOKIES_FILE="${CURRENT_DIR}/login_cookies.txt"
TEMP_FILES_PREFIX="${CURRENT_DIR}/temp/page_response_"
SKIP_KEYWORDS_LIST=('Répondre' 'test' 'Responder' 'Risposta' '点赞' '2h ago' 'Alle Leistungen anzeigen' 'Скрыть' 'Come' 'Like' 'Sport' 'Reply' 'Plattform' 'Platforma' 'Platform' '250 Euro')
MAX_ATTEMPTS=3
TOMORROW_TIMESTAMP=$(date -d 'tomorrow' +%s)
EXTRA_COOKIES="_ym_uid=${TOMORROW_TIMESTAMP}931665485; _ym_d=${TOMORROW_TIMESTAMP}; _ym_isad=2; _ym_visorc=w;"


# Common HTTP headers
HEADER_ACCEPT='accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
HEADER_ACCEPT_LANGUAGE='accept-language: en-US,en;q=0.9'
HEADER_CACHE_CONTROL='cache-control: no-cache'
HEADER_PRAGMA='pragma: no-cache'
HEADER_PRIORITY='priority: u=0, i'
HEADER_SEC_CH_UA='sec-ch-ua: "Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"'
HEADER_SEC_CH_UA_MOBILE='sec-ch-ua-mobile: ?0'
HEADER_SEC_CH_UA_PLATFORM='sec-ch-ua-platform: "Windows"'
HEADER_SEC_FETCH_DEST='sec-fetch-dest: document'
HEADER_SEC_FETCH_MODE='sec-fetch-mode: navigate'
HEADER_SEC_FETCH_SITE='sec-fetch-site: same-origin'
HEADER_SEC_FETCH_USER='sec-fetch-user: ?1'
HEADER_UPGRADE_INSECURE_REQUESTS='upgrade-insecure-requests: 1'
HEADER_USER_AGENT='user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36'
HEADER_CONTENT_TYPE='content-type: application/x-www-form-urlencoded'
HEADER_ORIGIN="origin: https://${DOMAIN}"

LAST_SENT_ID=$(cat $POSITIONS_FILE | tail -n 1)
if [ -z "$LAST_SENT_ID" ]; then
    LAST_SENT_ID=0
fi

echo "--------------START POSITION $LAST_SENT_ID------------------"

# Detect curl command - prefer curl.exe on Windows to avoid PowerShell aliases
if command -v curl.exe >/dev/null 2>&1; then
    CURL_CMD="curl.exe"
else
    CURL_CMD="curl"
fi

nl2nlll() {
    local string="${1}"
    # Replace newlines and carriage returns with URL-encoded equivalents
    # Use printf to preserve the string, then use tr to replace actual newline/carriage return characters
    # Use control characters (\001 and \002) as temporary placeholders that won't appear in normal text
    local encoded=$(printf '%s' "$string" | tr '\r' '\001' | tr '\n' '\002' | sed 's/\001/%0D/g; s/\002/%0A/g')
    echo "${encoded}"
}

send_to_telegram() {
    echo "Delaying for $DELAY_SECONDS seconds..."
    sleep $DELAY_SECONDS

    local message="$1"
    local chat_id="$2"
    local image_url="${3:-}"  # Optional: URL to image to download and send
    local zip_file="${4:-}"   # Optional: Path to zip file to send as document

   

    if [ "$DEBUG_DATA" -eq 1 ]; then
        echo -e "${RED}--------------------------------${NC}"
        echo -e "${RED}NO REAL SEND: $message${NC}"
        echo -e "${RED}--------------------------------${NC}"
        return 0
    else
        #echo -e "\033[0;32mSending to Telegram: $message\033[0m"
        echo -e "${GREEN}--------------------------------${NC}"
        echo -e "${GREEN}REAL SEND: $message${NC}"
        echo -e "${GREEN}--------------------------------${NC}"
    fi

    # For JSON in Telegram API, we need to escape JSON special characters
    # The message may contain HTML entities (like &#039;) which should be preserved
    # Escape: backslashes, double quotes, and convert newlines to \n
    # Use jq if available for proper JSON escaping, otherwise use sed
    if command -v jq >/dev/null 2>&1; then
        # jq properly escapes JSON strings
        message_encoded=$(printf '%s' "$message" | jq -Rs . | sed 's/^"//; s/"$//')
    else
        # Manual escaping: escape backslashes first, then quotes, then handle newlines
        # Use printf to preserve all characters, then escape
        message_encoded=$(printf '%s' "$message" | \
            sed 's/\\/\\\\/g' | \
            sed 's/"/\\"/g' | \
            awk 'BEGIN{RS="";ORS=""} {gsub(/\r/,""); gsub(/\n/,"\\n"); print}')
    fi
    
    local temp_image_file=""
    local image_base64=""
    local media_items=()
    
    # Download and process image if URL is provided
    local has_photo=false
    if [ -n "$image_url" ]; then
        image_base64=$(image_download "$image_url")
        if [ -n "$image_base64" ]; then
            temp_image_file="${TEMP_FILES_PREFIX}$$.telegram_img.png"
            # Decode base64 to temp file
            if echo "$image_base64" | base64 -d > "$temp_image_file" 2>/dev/null; then
                if [ -f "$temp_image_file" ] && [ -s "$temp_image_file" ]; then
                    media_items+=("{\"type\":\"photo\",\"media\":\"attach://photo\"}")
                    has_photo=true
                else
                    rm -f "$temp_image_file"
                    temp_image_file=""
                fi
            else
                temp_image_file=""
            fi
        fi
    fi
    
    # Add document if zip_file is provided
    local has_document=false
    if [ -n "$zip_file" ] && [ -f "$zip_file" ]; then
        media_items+=("{\"type\":\"document\",\"media\":\"attach://document\"}")
        has_document=true
    fi
    
    # Telegram doesn't allow mixing document with photo in media group
    # If we have both, send both as documents in a media group (one message)
    if [ "$has_photo" = true ] && [ "$has_document" = true ]; then
        # Send both photo and zip as documents in a media group
        if [ "$TG_DEBUGER" = true ]; then
            echo "DEBUG: Mixed media types detected, sending both as documents in media group" >&2
        fi
        
        # Build JSON dynamically based on which files exist (both are optional)
        # Escape the message for JSON: backslashes, quotes, newlines, carriage returns
        local caption_escaped=""
        if command -v awk >/dev/null 2>&1; then
            # awk can handle newlines properly - use RS="" to read entire input, then replace newlines
            caption_escaped=$(printf '%s' "$message" | awk 'BEGIN{RS="";ORS=""} {gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\r/, ""); gsub(/\n/, "\\n"); print}')
        else
            # Fallback: use tr to convert newlines to a placeholder, then sed, then convert back
            caption_escaped=$(printf '%s' "$message" | tr '\n' '\001' | tr '\r' '\002' | sed 's/\\/\\\\/g; s/"/\\"/g; s/\001/\\n/g; s/\002//g')
        fi
        
        # Build JSON array dynamically based on available files
        local media_json="["
        local file_counter=1
        local first_item=true
        
        # Add image file if it exists
        if [ -n "$temp_image_file" ] && [ -f "$temp_image_file" ]; then
            if [ "$first_item" = true ]; then
                media_json="${media_json}{\"type\":\"document\",\"media\":\"attach://file${file_counter}\",\"caption\":\"${caption_escaped}\",\"parse_mode\":\"HTML\"}"
                first_item=false
            else
                media_json="${media_json},{\"type\":\"document\",\"media\":\"attach://file${file_counter}\"}"
            fi
            file_counter=$((file_counter + 1))
        fi
        
        # Add zip file if it exists
        if [ -n "$zip_file" ] && [ -f "$zip_file" ]; then
            if [ "$first_item" = true ]; then
                media_json="${media_json}{\"type\":\"document\",\"media\":\"attach://file${file_counter}\",\"caption\":\"${caption_escaped}\",\"parse_mode\":\"HTML\"}"
                first_item=false
            else
                media_json="${media_json},{\"type\":\"document\",\"media\":\"attach://file${file_counter}\"}"
            fi
            file_counter=$((file_counter + 1))
        fi
        
        media_json="${media_json}]"
        
        # Only proceed if we have at least one file
        if [ "$file_counter" -eq 1 ]; then
            echo "WARNING: No files to send in media group" >&2
            return 1
        fi
        
        # Validate with jq if available (but don't rebuild, just check)
        if command -v jq >/dev/null 2>&1; then
            if ! echo "$media_json" | jq . >/dev/null 2>&1; then
                echo "WARNING: JSON validation failed, but proceeding anyway" >&2
            fi
        fi
        
        if [ "$TG_DEBUGER" = true ]; then
            # Debug output - always show for troubleshooting
            echo "DEBUG: media_json: $media_json" >&2
            echo "DEBUG: temp_image_file: $temp_image_file" >&2
            echo "DEBUG: zip_file: $zip_file" >&2
        fi
        # Validate JSON if jq is available
        if command -v jq >/dev/null 2>&1; then
            if ! echo "$media_json" | jq . >/dev/null 2>&1; then
                echo "ERROR: Invalid JSON generated!" >&2
                echo "$media_json" | jq . >&2 || echo "$media_json" >&2
            else
                echo "DEBUG: JSON is valid" >&2
            fi
        fi
        
        # Build file attachment arguments dynamically (both files are optional)
        local curl_file_args=()
        local attach_counter=1
        
        if [ -n "$temp_image_file" ] && [ -f "$temp_image_file" ]; then
            curl_file_args+=(-F "file${attach_counter}=@${temp_image_file}")
            if [ "$DEBUG_DATA" -eq 1 ]; then
                echo "DEBUG: Image file exists, size: $(stat -f%z "$temp_image_file" 2>/dev/null || stat -c%s "$temp_image_file" 2>/dev/null || echo "unknown") bytes" >&2
            fi
            attach_counter=$((attach_counter + 1))
        else
            echo "DEBUG: Image file not provided or not found: $temp_image_file" >&2
        fi
        
        if [ -n "$zip_file" ] && [ -f "$zip_file" ]; then
            curl_file_args+=(-F "file${attach_counter}=@${zip_file}")
            if [ "$DEBUG_DATA" -eq 1 ]; then
                echo "DEBUG: Zip file exists, size: $(stat -f%z "$zip_file" 2>/dev/null || stat -c%s "$zip_file" 2>/dev/null || echo "unknown") bytes" >&2
            fi
            attach_counter=$((attach_counter + 1))
        else
            echo "DEBUG: Zip file not provided or not found: $zip_file" >&2
        fi
        
        # Pass JSON directly - ensure it's treated as a string literal
        # Use --form-string which doesn't URL-encode the value
        # Only include file attachments that exist
        local result=$($CURL_CMD -s -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMediaGroup" \
            -F "chat_id=${chat_id}" \
            --form-string "media=$media_json" \
            "${curl_file_args[@]}")
        
        # Clean up
        if [ -n "$temp_image_file" ] && [ -f "$temp_image_file" ]; then
            rm -f "$temp_image_file"
        fi
        if [ -n "$zip_file" ] && [ -f "$zip_file" ]; then
            rm -f "$zip_file"
        fi
        
        # Check results
        echo "Sent to Telegram: ${message}"
        if [ "$DEBUG_DATA" -eq 1 ] || echo "$result" | grep -q '"ok":false'; then
            echo "Result: $result"
        else
            echo "Media group sent successfully"
        fi
        echo ""
        echo "--------------------------------"
        return 0
    fi
    
    # Build curl command arguments for single media type
    if [ ${#media_items[@]} -gt 0 ]; then
        # Build JSON array for media items using jq if available for proper JSON construction
        local media_json=""
        if command -v jq >/dev/null 2>&1; then
            # Use jq to properly construct JSON array
            local first=true
            local jq_input=""
            for item in "${media_items[@]}"; do
                # Parse the item JSON to extract type and media
                local item_type=$(echo "$item" | jq -r '.type')
                local item_media=$(echo "$item" | jq -r '.media')
                if [ "$first" = true ]; then
                    # Build JSON object with jq for proper escaping - use message (not message_encoded) and let jq escape it
                    local media_obj=$(echo -n "$message" | jq -Rs --arg type "$item_type" --arg media "$item_media" '{type: $type, media: $media, caption: ., parse_mode: "HTML"}')
                    jq_input="$media_obj"
                    first=false
                else
                    local media_obj=$(jq -n --arg type "$item_type" --arg media "$item_media" '{type: $type, media: $media}')
                    jq_input="${jq_input},${media_obj}"
                fi
            done
            # Build the final array
            media_json=$(echo "[$jq_input]" | jq -c .)
        else
            # Manual JSON construction (fallback)
            local media_json="["
            local first=true
            for item in "${media_items[@]}"; do
                if [ "$first" = true ]; then
                    # Remove the closing brace
                    local item_length=${#item}
                    local item_without_brace="${item:0:$((item_length-1))}"
                    # Build the complete item with caption and parse_mode
                    local item_with_caption="${item_without_brace},\"caption\":\"${message_encoded}\",\"parse_mode\":\"HTML\"}"
                    media_json="${media_json}${item_with_caption}"
                    first=false
                else
                    media_json="${media_json},${item}"
                fi
            done
            media_json="${media_json}]"
        fi
        
        if [ "$TG_DEBUGER" = true ]; then
            # Debug output - always show for troubleshooting
            echo "DEBUG: media_json: $media_json" >&2
            echo "DEBUG: message_encoded length: ${#message_encoded}" >&2
            echo "DEBUG: message_encoded (first 200 chars): ${message_encoded:0:200}" >&2
        fi
        
        # Validate JSON if jq is available
        if command -v jq >/dev/null 2>&1; then
            if ! echo "$media_json" | jq . >/dev/null 2>&1; then
                echo "ERROR: Invalid JSON generated!" >&2
                echo "JSON: $media_json" >&2
            else
                echo "DEBUG: JSON is valid" >&2
            fi
        fi
        
        local curl_args=(
            -s -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMediaGroup"
            -F "chat_id=${chat_id}"
            -F "media=${media_json}"
        )
        
        # Add file attachments
        if [ -n "$zip_file" ] && [ -f "$zip_file" ]; then
            curl_args+=(-F "document=@${zip_file}")
        fi
        if [ -n "$temp_image_file" ] && [ -f "$temp_image_file" ]; then
            curl_args+=(-F "photo=@${temp_image_file}")
        fi
    else
        # No media, send text message only (when both image_url and zip_file are empty/not provided)
        local curl_args=(
            -s -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage"
            -d "chat_id=${chat_id}"
            --data-urlencode "parse_mode=HTML"
            --data-urlencode "text=$(htmlencode "$message")"
        )
    fi

    if [ $DEBUG_DATA -eq 1 ]; then
        echo "DEBUG: curl_args:" >&2
        printf "  %s\n" "${curl_args[@]}" >&2
    fi

    result=$($CURL_CMD "${curl_args[@]}")
    
    # Clean up the temporary file
    #if [ -n "$temp_image_file" ] && [ -f "$temp_image_file" ]; then
       # rm -f "$temp_image_file"
    #fi
    if [ -n "$zip_file" ] && [ -f "$zip_file" ]; then
        rm -f "$zip_file"
    fi
    # Check if result contains an error or if debug is enabled
    if [ "$DEBUG_DATA" -eq 1 ] || echo "$result" | grep -q '"ok":false'; then
        echo "Sent to Telegram: ${message}"
        echo "Result: $result"
    fi
    echo ""
    echo "--------------------------------"
}

htmlencode() {
    local string="${1}"
    #local encoded=$(echo "$string" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&apos;/g')
    local encoded=$(echo "$string" | sed 's/&/%26/g; s/</\&lt;/g; s/\&gt;/>/g; s/\&quot;/"/g; s/'"'"'/\&apos;/g')
    echo "${encoded}"
}

# Function to URL encode a string
urlencode() {
    local string="${1}"
    local strlen=${#string}
    local encoded=""
    local pos c o

    for (( pos=0 ; pos<strlen ; pos++ )); do
        c=${string:$pos:1}
        case "$c" in
            [-_.~a-zA-Z0-9] ) o="${c}" ;;
            * ) printf -v o '%%%02x' "'$c"
        esac
        encoded+="${o}"
    done
    echo "${encoded}"
}

# Function to update the global COOKIES variable from the cookie file and EXTRA_COOKIES
update_cookies_from_file() {
    if [ ! -f "$COOKIES_FILE" ]; then
        return
    fi

    # Extract cookies from the cookie jar file
    # curl saves cookies in Netscape format: domain, flag, path, secure, expiration, name, value
    # All fields are tab-separated
    local cookie_parts=()
    while IFS=$'\t' read -r domain flag path secure expiration name value rest; do
        # Skip comments and empty lines
        [[ "$domain" =~ ^# ]] && continue
        [[ -z "$domain" ]] && continue
        
        # Check if we have at least name and value (fields 5 and 6)
        if [ -n "$name" ] && [ -n "$value" ]; then
            # Skip expired cookies (expiration is a timestamp, 0 means session cookie)
            if [ "$expiration" != "0" ] && [ -n "$expiration" ]; then
                local current_time=$(date +%s)
                if [ "$expiration" -lt "$current_time" ] 2>/dev/null; then
                    continue  # Skip expired cookies
                fi
            fi
            cookie_parts+=("${name}=${value}")
        fi
    done < "$COOKIES_FILE"
    
    # Join cookies from file with semicolon and space
    local cookies_from_file=""
    if [ ${#cookie_parts[@]} -gt 0 ]; then
        cookies_from_file=$(IFS='; '; echo "${cookie_parts[*]}")
        # echo "Extracted ${#cookie_parts[@]} cookies from file"
    fi
    
    # Combine EXTRA_COOKIES with cookies from file
    if [ -n "$EXTRA_COOKIES" ] && [ -n "$cookies_from_file" ]; then
        # Remove trailing semicolon and space from EXTRA_COOKIES if present
        local extra_cookies_clean="${EXTRA_COOKIES%; }"
        extra_cookies_clean="${extra_cookies_clean%;}"
        COOKIES="${extra_cookies_clean}; ${cookies_from_file}"
        # echo "Combined cookies: ${COOKIES}"
    elif [ -n "$EXTRA_COOKIES" ]; then
        # Only EXTRA_COOKIES available
        local extra_cookies_clean="${EXTRA_COOKIES%; }"
        extra_cookies_clean="${extra_cookies_clean%;}"
        COOKIES="$extra_cookies_clean"
    elif [ -n "$cookies_from_file" ]; then
        # Only cookies from file available
        COOKIES="$cookies_from_file"
    else
        COOKIES=""
    fi
}

# Login function to get cookies from response
login() { 
    local provided_csrf_token="$1"
    echo "Logging in..."
    
    local csrf_token=""
    
    # If CSRF token was provided, use it; otherwise, fetch from login page
    if [ -n "$provided_csrf_token" ]; then
        echo "Using provided CSRF token"
        csrf_token="$provided_csrf_token"
    else
        echo "Fetching CSRF token from login page"
        # Fetch the login page to extract CSRF token and initial cookies
        # Use -b and -c to handle session state, and EXTRA_COOKIES for consistency
        local login_page_response=$($CURL_CMD -s -b "$COOKIES_FILE" -c "$COOKIES_FILE" "https://${DOMAIN}/login" \
          -H "$HEADER_ACCEPT" \
          -H 'accept-language: en-US,en;q=0.9,ru;q=0.8' \
          -H "$HEADER_CACHE_CONTROL" \
          -H "$HEADER_PRAGMA" \
          -H "$HEADER_PRIORITY" \
          -H "referer: https://${DOMAIN}/login" \
          -H "$HEADER_SEC_CH_UA" \
          -H "$HEADER_SEC_CH_UA_MOBILE" \
          -H "$HEADER_SEC_CH_UA_PLATFORM" \
          -H "$HEADER_SEC_FETCH_DEST" \
          -H "$HEADER_SEC_FETCH_MODE" \
          -H "$HEADER_SEC_FETCH_SITE" \
          -H "$HEADER_SEC_FETCH_USER" \
          -H "$HEADER_UPGRADE_INSECURE_REQUESTS" \
          -H "$HEADER_USER_AGENT" \
          -H "Cookie: $EXTRA_COOKIES")

        # Update global COOKIES variable from file
        update_cookies_from_file

        # Extract CSRF token from the login page
        csrf_token=$(echo "$login_page_response" | grep -oP 'name="_token" value="\K[^"]+')
        
        if [ -z "$csrf_token" ]; then
            echo "Error: Could not extract CSRF token from login page"
            return 1
        fi
    fi
    
    # Perform login POST request and save cookies
    # Using --data-urlencode for proper URL encoding
    local login_response=$($CURL_CMD -s -i -b "$COOKIES_FILE" -c "$COOKIES_FILE" "https://${DOMAIN}/login" \
      -H "$HEADER_ACCEPT" \
      -H 'accept-language: en-US,en;q=0.9,ru;q=0.8' \
      -H "$HEADER_CACHE_CONTROL" \
      -H "$HEADER_CONTENT_TYPE" \
      -H "$HEADER_ORIGIN" \
      -H "$HEADER_PRAGMA" \
      -H "$HEADER_PRIORITY" \
      -H "referer: https://${DOMAIN}/login" \
      -H "$HEADER_SEC_CH_UA" \
      -H "$HEADER_SEC_CH_UA_MOBILE" \
      -H "$HEADER_SEC_CH_UA_PLATFORM" \
      -H "$HEADER_SEC_FETCH_DEST" \
      -H "$HEADER_SEC_FETCH_MODE" \
      -H "$HEADER_SEC_FETCH_SITE" \
      -H "$HEADER_SEC_FETCH_USER" \
      -H "$HEADER_UPGRADE_INSECURE_REQUESTS" \
      -H "$HEADER_USER_AGENT" \
      -H "Cookie: $EXTRA_COOKIES" \
      --data-urlencode "_token=${csrf_token}" \
      --data-urlencode "email=${LOGIN_EMAIL}" \
      --data-urlencode "password=${LOGIN_PASSWD}" \
      --data-urlencode "remember=1")
    
    update_cookies_from_file
    
    if [ -z "$COOKIES" ]; then
        echo "Error: Login failed - no cookies received"
        return 1
    fi
    
    echo "Login successful. Cookies obtained."
    return 0
}

image_download() {
    local image_file="${TEMP_FILES_PREFIX}$$.img.png"
    local image_url="$1"
    
    # Clean and validate the URL
    image_url=$(echo "$image_url" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr -d '\n\r')
    
    # Check if URL is empty
    if [ -z "$image_url" ]; then
        echo -e "\033[0;31mEmpty image URL provided\033[0m" >&2
        echo ""
        return
    fi
    
    # If URL is relative, make it absolute
    if [[ "$image_url" =~ ^/ ]]; then
        image_url="https://${DOMAIN}${image_url}"
    fi
    
    # Validate URL format (basic check)
    if [[ ! "$image_url" =~ ^https?:// ]]; then
        echo -e "\033[0;31mInvalid URL format: $image_url\033[0m" >&2
        echo ""
        return
    fi
    if [[ "$DEBUG_DATA" -eq 1 ]]; then
        echo "Downloading image from $image_url" >&2
        echo "DEBUG: Cleaned URL: $image_url" >&2
        echo "DEBUG: URL length: ${#image_url}" >&2
    fi
    # Use -- to separate options from URL (helps with Windows curl.exe)
    local http_code=$($CURL_CMD -s -L -b "$COOKIES_FILE" -c "$COOKIES_FILE" -o "$image_file" -w "%{http_code}" \
    -H "$HEADER_ACCEPT" \
    -H "$HEADER_ACCEPT_LANGUAGE" \
    -H "$HEADER_CACHE_CONTROL" \
    -H "$HEADER_PRAGMA" \
    -H "$HEADER_PRIORITY" \
    -H "referer: https://${DOMAIN}/" \
    -H "$HEADER_SEC_CH_UA" \
    -H "$HEADER_SEC_CH_UA_MOBILE" \
    -H "$HEADER_SEC_CH_UA_PLATFORM" \
    -H "$HEADER_SEC_FETCH_DEST" \
    -H "$HEADER_SEC_FETCH_MODE" \
    -H "$HEADER_SEC_FETCH_SITE" \
    -H "$HEADER_SEC_FETCH_USER" \
    -H "$HEADER_UPGRADE_INSECURE_REQUESTS" \
    -H "$HEADER_USER_AGENT" \
    -H "Cookie: $EXTRA_COOKIES" \
    -- "$image_url")
    
    update_cookies_from_file
    
    # Debug output
    if [[ "$DEBUG_DATA" -eq 1 ]]; then
        echo "DEBUG: HTTP code: $http_code" >&2
        echo "DEBUG: Image file path: $image_file" >&2
        echo "DEBUG: Image file exists: $([ -f "$image_file" ] && echo "yes" || echo "no")" >&2
    fi
    if [ -f "$image_file" ]; then
        # Get file size
        local debug_file_size=0
        if command -v stat >/dev/null 2>&1; then
            debug_file_size=$(stat -c%s "$image_file" 2>/dev/null || stat -f%z "$image_file" 2>/dev/null || echo "0")
        else
            debug_file_size=$(wc -c < "$image_file" 2>/dev/null || echo "0")
        fi
        if [[ "$DEBUG_DATA" -eq 1 ]]; then
            echo "DEBUG: Image file size: $debug_file_size bytes" >&2
        fi
        # Check file type if available
        if command -v file >/dev/null 2>&1; then
            if [[ "$DEBUG_DATA" -eq 1 ]]; then
                echo "DEBUG: Image file type: $(file -b "$image_file" 2>/dev/null || echo "unknown")" >&2
            fi
        fi
        
        # Show first 200 bytes to check if it's HTML/error
        if [ "$debug_file_size" -gt 0 ]; then
            local first_bytes=$(head -c 200 "$image_file" 2>/dev/null | tr -d '\0' | head -c 200)
            if [[ "$DEBUG_DATA" -eq 1 ]]; then
                if echo "$first_bytes" | grep -qi "<html\|<!DOCTYPE\|error"; then
                    echo "DEBUG: File appears to be HTML/error page (first bytes: ${first_bytes:0:100}...)" >&2
                else
                    echo "DEBUG: File appears to be binary/image data" >&2
                fi
            fi
        fi
    fi
    
    if [ "$http_code" = "200" ] && [ -f "$image_file" ]; then
        # Check if file is not empty and is a valid image
        local file_size=0
        if [ -f "$image_file" ]; then
            # Get file size (works on both Linux and Windows)
            if command -v stat >/dev/null 2>&1; then
                file_size=$(stat -c%s "$image_file" 2>/dev/null || stat -f%z "$image_file" 2>/dev/null || echo "0")
            else
                # Fallback for systems without stat
                file_size=$(wc -c < "$image_file" 2>/dev/null || echo "0")
            fi
        fi
        
        # Check if file has content and is likely an image (not HTML error page)
        if [ "$file_size" -gt 100 ] && ! head -c 100 "$image_file" 2>/dev/null | grep -qi "<html\|<!DOCTYPE\|error"; then
            if [[ "$DEBUG_DATA" -eq 1 ]]; then
                echo "DEBUG: File validation passed, encoding to base64..." >&2
            fi
            # Return base64-encoded image data
            if command -v base64 >/dev/null 2>&1; then
                # Try with -w 0 first (Linux), fallback to without (macOS/Windows)
                local base64_result=$(base64 -w 0 "$image_file" 2>/dev/null || base64 "$image_file" 2>/dev/null | tr -d '\n')
                if [ -n "$base64_result" ]; then
                    if [[ "$DEBUG_DATA" -eq 1 ]]; then
                        echo "DEBUG: Base64 encoding successful (length: ${#base64_result} chars)" >&2
                    fi
                    echo "$base64_result"
                else
                    if [[ "$DEBUG_DATA" -eq 1 ]]; then
                        echo "DEBUG: Base64 encoding failed or produced empty result" >&2
                    fi
                    rm -f "$image_file"
                    echo ""
                fi
            else
                echo -e "\033[0;31mError: base64 command not found\033[0m" >&2
                rm -f "$image_file"
                echo ""
                return
            fi
            # Clean up the temporary file
            rm -f "$image_file"
        else
            echo "Warning: Downloaded file is empty or not a valid image (size: $file_size)" >&2
            rm -f "$image_file"
            echo ""
        fi
    else
        echo "Warning: Failed to download image (HTTP code: $http_code)" >&2
        if [ "$http_code" = "000" ]; then
            echo "DEBUG: HTTP 000 usually means curl connection failed. Check network/cookies." >&2
        fi
        # Clean up on failure too
        rm -f "$image_file"
        echo ""
    fi
}

# Function to get IDs from pages
# Populates the global IDS_LIST array
get_ids() {
    for i in $(seq 1 $MAX_PAGES_BACK); do
        echo "Page Number $i"
        SCANURL=''
        if [ "$i" -gt 1 ]; then
            echo "${LINK_URL}&page=${i}"
            SCANURL="${LINK_URL}&page=${i}"
        else
            echo "${LINK_URL}"
            SCANURL="${LINK_URL}"
        fi
        
        # Retry logic: up to 3 attempts
        local attempt=1
        local success=0
        
        while [ $attempt -le $MAX_ATTEMPTS ] && [ $success -eq 0 ]; do
            if [ $attempt -gt 1 ]; then
                echo "Retry attempt $attempt of $MAX_ATTEMPTS for page $i"
            fi
            
            # Get HTTP status code and response body
            # -L flag follows redirects (e.g., 302)
            # -b reads initial cookies, -c updates the file with any Set-Cookie from response
            local temp_file="${TEMP_FILES_PREFIX}$$.txt"
            if [ $DEBUG_DATA -eq 1 ]; then
                echo "DEBUG: TEMP FILES PREFIX: ${TEMP_FILES_PREFIX}"
                echo "DEBUG: Temp file path: $temp_file" >&2
                echo "DEBUG: Cookies file: $COOKIES_FILE" >&2
                echo "DEBUG: URL: $SCANURL" >&2
            fi
            
            # Run curl and capture both exit code and HTTP status
            # curl -w writes HTTP code to stdout AFTER -o writes body to file
            # So we need to capture stdout separately
            local http_code_file="${TEMP_FILES_PREFIX}$$_httpcode.txt"
            local http_code="000"
            local curl_exit_code=0
            
            # Run curl: body goes to temp_file (-o), HTTP code goes to stdout (-w), errors to stderr
            # We redirect stdout (HTTP code) to http_code_file, stderr to see errors
            $CURL_CMD -s -L -b "$COOKIES_FILE" -c "$COOKIES_FILE" \
              -o "$temp_file" \
              -w "%{http_code}" \
              "$SCANURL" \
              -H "$HEADER_ACCEPT" \
              -H "$HEADER_ACCEPT_LANGUAGE" \
              -H "$HEADER_CACHE_CONTROL" \
              -H "$HEADER_PRAGMA" \
              -H "$HEADER_PRIORITY" \
              -H "referer: https://${DOMAIN}/" \
              -H "$HEADER_SEC_CH_UA" \
              -H "$HEADER_SEC_CH_UA_MOBILE" \
              -H "$HEADER_SEC_CH_UA_PLATFORM" \
              -H "$HEADER_SEC_FETCH_DEST" \
              -H "$HEADER_SEC_FETCH_MODE" \
              -H "$HEADER_SEC_FETCH_SITE" \
              -H "$HEADER_SEC_FETCH_USER" \
              -H "$HEADER_UPGRADE_INSECURE_REQUESTS" \
              -H "$HEADER_USER_AGENT" \
              -H "Cookie: $EXTRA_COOKIES" > "$http_code_file" 2>&1
            curl_exit_code=$?
            
            # Read HTTP code from the file (last 3 characters should be the HTTP code)
            if [ -f "$http_code_file" ]; then
                http_code=$(cat "$http_code_file" | tr -d '\n\r' | tail -c 3)
                # If http_code is empty or not 3 digits, it might be an error message
                if [ ${#http_code} -ne 3 ] || ! [[ "$http_code" =~ ^[0-9]{3}$ ]]; then
                    if [ $DEBUG_DATA -eq 1 ]; then
                        echo "DEBUG: Invalid HTTP code from file, content: $(cat "$http_code_file")" >&2
                    fi
                    http_code="000"
                fi
                rm -f "$http_code_file"
            fi
            
            if [ $DEBUG_DATA -eq 1 ]; then
                echo "DEBUG: Curl exit code: $curl_exit_code" >&2
                echo "DEBUG: HTTP code: $http_code" >&2
                if [ -f "$temp_file" ]; then
                    local file_size=$(stat -c%s "$temp_file" 2>/dev/null || stat -f%z "$temp_file" 2>/dev/null || wc -c < "$temp_file" 2>/dev/null || echo "0")
                    echo "DEBUG: Temp file exists, size: $file_size bytes" >&2
                else
                    echo "DEBUG: Temp file does NOT exist" >&2
                fi
            fi
            
            # Update the global COOKIES variable from the updated file
            update_cookies_from_file
            
            # Check if curl was successful and HTTP status is OK
            if [ $curl_exit_code -eq 0 ] && [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
                # Verify the file was created
                if [ ! -f "$temp_file" ]; then
                    echo -e "\033[0;31mError: Temp file was not created: $temp_file (HTTP: $http_code, Curl exit: $curl_exit_code)\033[0m" >&2
                    attempt=$((attempt + 1))
                    continue
                fi
                # Extract IDs from response
                newids=($(grep -oP '/viewer/\K[0-9]+(?=/view)' "$temp_file"))
                
                # Check if we got any IDs
                if [ ${#newids[@]} -gt 0 ]; then
                    echo "Found ${#newids[@]} IDs on page $i"
                    if [ $DEBUG_DATA -eq 1 ]; then
                        echo "newids: ${newids[@]}"
                    fi
                    IDS_LIST+=("${newids[@]}")
                    # Extra code to read structured data (id, description, img_url, country, date)
                    # We process the file card by card
                    # First, we get the indices of each card start
                    local card_starts=($(grep -n "<a href=\"https://${DOMAIN}/viewer/[0-9]\+/view\"" "$temp_file" | cut -d: -f1))
                    local total_lines=$(wc -l < "$temp_file")
                    for idx in "${!card_starts[@]}"; do
                        local start_line=${card_starts[$idx]}
                        local end_line=$total_lines
                        if [ $((idx + 1)) -lt ${#card_starts[@]} ]; then
                            end_line=${card_starts[$((idx + 1))]}
                        fi
                        
                        # Extract the card block
                        local card_block=$(sed -n "${start_line},${end_line}p" "$temp_file")
                        
                        # Extract fields using PCRE grep -oP
                        local ad_id=$(echo "$card_block" | grep -oP '/viewer/\K[0-9]+(?=/view)' | head -1)
                        local ad_desc=$(echo "$card_block" | grep -zoP '<p class="card-subtitle">\s*\K[^<]+(?=\s*</p>)' | tr -d '\0' | sed 's/^[ \t]*//;s/[ \t]*$//')
                        local ad_img=$(echo "$card_block" | grep -zoP 'class="card-body[^"]*">\s*<img src="\K[^"]+(?=")' | tr -d '\0')
                        local ad_country=$(echo "$card_block" | grep -oP '/flags/\K[^.]+(?=\.svg)' | head -1)
                        local ad_date=$(echo "$card_block" | grep -zoP '<div class="card-footer">[\s\S]*?<div>\s*\K[0-9]+ [A-Za-z]+ [0-9]+(?=\s*</div>)' | tr -d '\0' | sed 's/^[ \t]*//;s/[ \t]*$//')
                        
                        # Format as a single string and add to list
                        # URL encode variables to handle special characters safely
                        #local ad_desc_encoded=$(urlencode "$ad_desc")
                        #local ad_img_encoded=$(urlencode "$ad_img")
                        #local ad_country_encoded=$(urlencode "$ad_country")
                        #local ad_date_encoded=$(urlencode "$ad_date")

                        local ad_data="ID:$ad_id | DESC:$ad_desc | IMG:$ad_img | COUNTRY:$ad_country | DATE:$ad_date"
                        ADS_DATA_LIST+=("$ad_data")
                        echo "  - Extracted: $ad_data"
                    done
                    success=1
                else                   
                    # Check if we got redirected to login page (session expired)
                    if grep -q "Login to your account" "$temp_file"; then
                        echo "Session expired - re-authenticating..."
                        cat "$temp_file";
                        # Extract CSRF token from the login page if available
                        local csrf_token=$(grep -oP 'name="_token" value="\K[^"]+' "$temp_file")
                        if [ -n "$csrf_token" ]; then
                            echo "Found CSRF token in response, using it for login"
                            # Re-authenticate using login function with the extracted CSRF token
                            login "$csrf_token"
                        else
                            echo "CSRF token not found in response, fetching from login page"
                            # Re-authenticate using login function (will fetch CSRF token)
                            login
                        fi
                        local login_result=$?
                        if [ $login_result -eq 0 ]; then
                            echo "Re-authentication successful, retrying page $i"
                            # Don't increment attempt, retry immediately with new cookies
                            continue
                        else
                            echo -e "\033[0;31mRe-authentication failed\033[0m"
                            # If login fails and we have empty credentials, break out to avoid infinite loop
                            if [ -z "$LOGIN_EMAIL" ] || [ -z "$LOGIN_PASSWD" ]; then
                                echo -e "\033[0;31mError: Login credentials are empty. Cannot re-authenticate. Exiting.\033[0m"
                                return 1
                            fi
                            # Increment attempt counter to avoid infinite loop
                            attempt=$((attempt + 1))
                            if [ $attempt -gt $MAX_ATTEMPTS ]; then
                                echo -e "\033[0;31mError: Failed to authenticate after $MAX_ATTEMPTS attempts. Exiting.\033[0m"
                                return 1
                            fi
                        fi
                    else
                        echo "Error: Page $i loaded (HTTP $http_code) but no IDs found"
                        echo "Returned HTML:";
                        if [ -f "$temp_file" ]; then
                            cat "$temp_file";
                        else
                            echo "Error: Temp file not found: $temp_file"
                        fi
                    fi
                    
                    if [ $attempt -eq $MAX_ATTEMPTS ]; then
                        echo "Failed to get IDs from page $i after $MAX_ATTEMPTS attempts"
                    fi
                fi
            else
                echo "Error: Failed to load page $i (HTTP status: $http_code, curl exit code: $?)"
                if [ $attempt -eq $MAX_ATTEMPTS ]; then
                    echo "Failed to load page $i after $MAX_ATTEMPTS attempts"
                fi
            fi
            # Clean up temp file
            rm -f "$temp_file"
            
            if [ $success -eq 0 ]; then
                attempt=$((attempt + 1))
                if [ $attempt -le $MAX_ATTEMPTS ]; then
                    sleep 1  # Wait 1 second before retry
                fi
            fi
        done
    done
    if [ "$DEBUG_DATA" -eq 1 ]; then
        echo "--------------DONE ToTAL IDS: ${#IDS_LIST[@]}------------------"
        echo "IDS_LIST: ${IDS_LIST[@]}"
        echo "SKIP_KEYWORDS_LIST: ${SKIP_KEYWORDS_LIST[@]}"
    fi
    return 0
}

# Function to extract keywords from HTML file
# Takes html_file path as parameter
# Returns keywords array via stdout (one keyword per line)
extract_kw() {
    local html_file="$1"
    # Extract all link texts from the HTML (handling strings with multiple words, trimming whitespace and quotes)
    local atags_array=()
    readarray -t atags_array < <(grep -oP '<a\b[^>]*>\K[^<]+(?=</a>)' "$html_file" | sed -E "s/^[[:space:]\"\“\”\‘\’\']+|[[:space:]\"\“\”\‘\’\']+$//g" | grep -v '^$')
    # Extract paragraphs and get only the first word from each
    local paragraphs_array=()
    readarray -t paragraphs_array < <(grep -oP '<p\b[^>]*>\K[^<]+(?=</p>)' "$html_file" | sed -E "s/^[[:space:]\"\“\”\‘\’\']+|[[:space:]\"\“\”\‘\’\']+$//g" | grep -v '^$' | awk '{print $1}')
    local bolds_array=()
    readarray -t bold_array < <(grep -oP '<b\b[^>]*>\K[^<]+(?=</b>)' "$html_file" | sed -E "s/^[[:space:]\"\“\”\‘\’\']+|[[:space:]\"\“\”\‘\’\']+$//g" | grep -v '^$' | awk '{print $1}')
    # Merge both arrays
    local merged_array=("${atags_array[@]}" "${paragraphs_array[@]}" "${bold_array[@]}")
    
    # Output merged array, one element per line
    printf '%s\n' "${merged_array[@]}"
}

# Function to get keywords from IDs
# Populates the global KEYWORDS_LIST array
# If an ID is provided as argument, processes only that ID (for retry)
get_keywords() {
    local target_ids=("${@:-${IDS_LIST[@]}}")
    for id in "${target_ids[@]}"; do
        echo "Processing ID: ${id}"
        if [ $id -le $LAST_SENT_ID ]; then
            echo "ID $id already sent, skipping"
            continue
        fi
        
        # Save response to a temporary file to check content if extraction fails
        local zip_file="${TEMP_FILES_PREFIX}${id}_zip_$$.zip"
        local html_file="${TEMP_FILES_PREFIX}${id}_page_$$.html"
        
        $CURL_CMD -sL -b "$COOKIES_FILE" -c "$COOKIES_FILE" "https://${DOMAIN}/viewer/${id}/zip" \
      -H "$HEADER_ACCEPT" \
      -H "$HEADER_ACCEPT_LANGUAGE" \
      -H "$HEADER_CACHE_CONTROL" \
      -H "$HEADER_PRAGMA" \
      -H "$HEADER_PRIORITY" \
      -H "referer: https://${DOMAIN}/viewer/${id}/view" \
      -H "$HEADER_SEC_CH_UA" \
      -H "$HEADER_SEC_CH_UA_MOBILE" \
      -H "$HEADER_SEC_CH_UA_PLATFORM" \
      -H "$HEADER_SEC_FETCH_DEST" \
      -H "$HEADER_SEC_FETCH_MODE" \
      -H "$HEADER_SEC_FETCH_SITE" \
      -H "$HEADER_SEC_FETCH_USER" \
      -H "$HEADER_UPGRADE_INSECURE_REQUESTS" \
      -H "$HEADER_USER_AGENT" \
      -H "Cookie: $EXTRA_COOKIES" -o "$zip_file"
        
        # Update cookies from the response immediately
        update_cookies_from_file
        
        # Check if we got redirected to login page (session expired)
        if grep -q "Login to your account" ${zip_file}; then
            echo "Session expired - re-authenticating..."
            # Extract CSRF token from the login page if available
            local csrf_token=$(grep -oP 'name="_token" value="\K[^"]+' ${zip_file})
            if [ -n "$csrf_token" ]; then
                echo "Found CSRF token in response, using it for login"
                # Re-authenticate using login function with the extracted CSRF token
                login "$csrf_token"
            else
                echo "CSRF token not found in response, fetching from login page"
                # Re-authenticate using login function (will fetch CSRF token)
                login
            fi
            if [ $? -eq 0 ]; then
                echo "Re-authentication successful, retrying download for ID $id"
                # Clean up the old zip file
                rm -f "$zip_file"
                # Re-download the zip file with new cookies
                $CURL_CMD -sL -b "$COOKIES_FILE" -c "$COOKIES_FILE" "https://${DOMAIN}/viewer/${id}/zip" \
                  -H "$HEADER_ACCEPT" \
                  -H "$HEADER_ACCEPT_LANGUAGE" \
                  -H "$HEADER_CACHE_CONTROL" \
                  -H "$HEADER_PRAGMA" \
                  -H "$HEADER_PRIORITY" \
                  -H "referer: https://${DOMAIN}/viewer/${id}/view" \
                  -H "$HEADER_SEC_CH_UA" \
                  -H "$HEADER_SEC_CH_UA_MOBILE" \
                  -H "$HEADER_SEC_CH_UA_PLATFORM" \
                  -H "$HEADER_SEC_FETCH_DEST" \
                  -H "$HEADER_SEC_FETCH_MODE" \
                  -H "$HEADER_SEC_FETCH_SITE" \
                  -H "$HEADER_SEC_FETCH_USER" \
                  -H "$HEADER_UPGRADE_INSECURE_REQUESTS" \
                  -H "$HEADER_USER_AGENT" \
                  -H "Cookie: $EXTRA_COOKIES" -o "$zip_file"
                # Update cookies again after retry
                update_cookies_from_file
                # Check if we still got a login page after re-authentication
                if grep -q "Login to your account" ${zip_file}; then
                    echo -e "\033[0;31mError: Still getting login page after re-authentication, retrying function for ID $id\033[0m"
                    rm -f "$zip_file" "$html_file"
                    get_keywords "$id"
                    continue
                fi
            else
                echo -e "\033[0;31mRe-authentication failed, retrying function for ID $id\033[0m"
                rm -f "$zip_file" "$html_file"
                get_keywords "$id"
                continue
            fi
        fi

        # Try to extract HTML from the downloaded file
        # If it's not a zip, bsdtar will fail or output nothing
        bsdtar -xO -f "$zip_file" "*.html" > "$html_file" 2>/dev/null
        
        url_in_file=$(grep -oP ' url: \K\S+' "$html_file" | head -1)

        if [ -n "$url_in_file" ]; then
            if [ $DEBUG_DATA -eq 1 ]; then
                echo "URL in file: $url_in_file"
            fi
            domain_name=$(echo "$url_in_file" | grep -oP 'https://\K[^/]+')
            if [ $DEBUG_DATA -eq 1 ]; then
                echo "Domain name: $domain_name"
            fi
            # Find the actual record in ADS_DATA_LIST by ID and add the LINK_URL property
            for idx in "${!ADS_DATA_LIST[@]}"; do
                if [[ "${ADS_DATA_LIST[$idx]}" == "ID:$id "* ]] || [[ "${ADS_DATA_LIST[$idx]}" == "ID:$id |"* ]]; then
                    ADS_DATA_LIST[$idx]="${ADS_DATA_LIST[$idx]} | LINK_URL:$url_in_file | DOMAIN_NAME:$domain_name | ZIP_FILE:$zip_file"
                    if [ $DEBUG_DATA -eq 1 ]; then
                        echo "  - Updated ADS_DATA_LIST record for ID $id with LINK_URL"
                    fi
                    break
                fi
            done
        fi
        # Extract keywords from HTML file using extract_kw function
        readarray -t keywords < <(extract_kw "$html_file")
        
        if [ ${#keywords[@]} -gt 0 ]; then
            echo "Keywords found: ${#keywords[@]}"
            # Show frequency for current ID (top 3)
            printf "%s\n" "${keywords[@]}" | sort | uniq -c | sort -rn | head -n 3
            
            # Add only top 3 phrases to global list
            readarray -t top_3_phrases < <(printf "%s\n" "${keywords[@]}" | sort | uniq -c | sort -rn | head -n 3 | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]+//')
            KEYWORDS_LIST+=("${top_3_phrases[@]}")
            
            # Find the first resulted Keyword with max repeats for this ID
            local top_entry=$(printf "%s\n" "${keywords[@]}" | sort | uniq -c | sort -rn | head -n 1)
            local top_count=$(echo "$top_entry" | awk '{print $1}')
            local top_keyword=$(echo "$top_entry" | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]+//')
            
            # Count alphabetic characters in top_keyword
            #if [ -n "$top_keyword" ] && [ "$top_count" -gt 2 ] && [[ "$top_keyword" =~ [a-zA-Z] ]]; then
            local alpha_count=$(echo "$top_keyword" | grep -o '[a-zA-Z]' | wc -l)
            if [ -n "$top_keyword" ] && [ "$top_count" -gt 2 ] && [ "$alpha_count" -gt 3 ]; then
                # Check if top_keyword is in SKIP_KEYWORDS_LIST
                local skip_this=0
                for skip_kw in "${SKIP_KEYWORDS_LIST[@]}"; do
                    if [ "$top_keyword" == "$skip_kw" ]; then
                        skip_this=1
                        break
                    fi
                done
                
                if [ $skip_this -eq 1 ]; then
                    echo "  - Skipping top keyword (in SKIP_KEYWORDS_LIST): $top_keyword"
                    continue
                fi

                # Check if it already exists in UNIQUE_KEYWORDS_LIST
                local already_exists=0
                for existing in "${UNIQUE_KEYWORDS_LIST[@]}"; do
                    if [ "$existing" == "$top_keyword" ]; then
                        already_exists=1
                        break
                    fi
                done
                
                # Add only if it does not exist
                if [ $already_exists -eq 0 ]; then
                    UNIQUE_KEYWORDS_LIST+=("$top_keyword")
                    echo "  - Added unique top keyword (count $top_count): $top_keyword"
                fi
            else
                echo "  - Skipping top keyword (count $top_count): $top_keyword"
                continue
            fi
        else
            echo "Error: No keywords found for ID ${id}"
            echo "Response content (first 200 chars):"
            # If it's HTML, cat it. If it's a zip but has no keywords, cat the extracted HTML.
            if [ -s "$html_file" ]; then
                #cat "$html_file"
                head -c 200 "$html_file"
            else
                # If no HTML was extracted, maybe the zip_file itself is an error page
                head -c 500 "$zip_file"
                echo -e "\n--- End of preview ---"
            fi
            #exit 1
        fi
        
        # Clean up temporary files
        #rm -f "$zip_file" "$html_file"
        #rm -f "$zip_file"
        rm -f "$html_file"
    done
}

# Function to count keyword frequency
count_keyword_frequency() {
    if [ ${#KEYWORDS_LIST[@]} -eq 0 ]; then
        echo "No keywords found to analyze."
        return
    fi
    echo -e "\n--- Keyword Frequency Analysis ---"
    # Print each element on a new line, sort them, count unique occurrences, sort by frequency descending
    printf "%s\n" "${KEYWORDS_LIST[@]}" | sort | uniq -c | sort -rn
}

#echo "old COOKIES: ${COOKIES}"
#login
#echo "new COOKIES:  ${COOKIES}"

get_ids
get_ids_exit_code=$?
if [ $get_ids_exit_code -ne 0 ]; then
    echo -e "\033[0;31mWarning: get_ids function returned with error code $get_ids_exit_code\033[0m" >&2
fi

echo "Total IDs found: ${#IDS_LIST[@]}"
if [ $DEBUG_DATA -eq 1 ]; then
    echo "${IDS_LIST[@]}"
fi

get_keywords

echo "Total Keywords found: ${#KEYWORDS_LIST[@]}"
if [ $DEBUG_DATA -eq 1 ]; then
    echo "${KEYWORDS_LIST[@]}"
fi

echo -e "\n--- Unique Top Keywords ---"
echo "Total unique top keywords: ${#UNIQUE_KEYWORDS_LIST[@]}"
#uniq_message="Total unique top keywords: ${#UNIQUE_KEYWORDS_LIST[@]}"$'\n'
uniq_message=""
for unique_kw in "${UNIQUE_KEYWORDS_LIST[@]}"; do
    echo " - $unique_kw"
    #uniq_message="${uniq_message}${unique_kw}"$'\n'
    #if [ "${unique_kw}" == "$KW_CONTENT" ]; then
    if [[ $KW_CONTENT =~ $unique_kw ]]; then
        echo "Keyword found in temp keywords file: $unique_kw"
        continue
    else
        echo "Keyword not found in temp keywords file: $unique_kw"
        echo "$unique_kw" >> "$TEMP_KW_FILE"
        uniq_message="${uniq_message}${unique_kw}"$'\n'
    fi
done

if [ ${#UNIQUE_KEYWORDS_LIST[@]} -gt 0 ] && [ -n "$uniq_message" ]; then
    echo -e "${GREEN}--> Sending to Telegram: $uniq_message${NC}"
    send_to_telegram "$uniq_message" "$TG_BOT_CHANNEL_TXT"

    echo "Last sent ID: $LAST_SENT_ID"
    echo "Adding to positions file: $LAST_SENT_ID"
    max_id=$(printf "%s\n" "${IDS_LIST[@]}" | sort -n | tail -n 1)
    echo "Max ID: $max_id"
    if [ "$max_id" -gt "$LAST_SENT_ID" ]; then
        echo "$max_id" > $POSITIONS_FILE
    fi
    
fi
# Call the frequency analysis function 
count_keyword_frequency

echo -e "\n--- Structured ADS Data ---"
send_info=0
#for ad in "${ADS_DATA_LIST[@]}"; do
# Iterate through ADS_DATA_LIST in reverse order
for ((idx=${#ADS_DATA_LIST[@]}-1; idx>=0; idx--)); do
    ad="${ADS_DATA_LIST[$idx]}"
    full_message="Full ADS Data:"$'\n'
    line_id=$(echo "$ad" | grep -oP 'ID:\K[0-9]+')
    if [ "$line_id" -gt "$LAST_SENT_ID" ]; then
        # Remove IMG:... field from the string before sending
        ad_img=$(echo "$ad" | grep -oP 'IMG:\K[^|]*')
        zip_file=$(echo "$ad" | grep -oP 'ZIP_FILE:\K[^|]*')
        ad_to_send=$(echo "$ad" | sed -E 's/ \| IMG:[^|]*/ /g')
        ad_to_send=$(echo "$ad_to_send" | sed -E 's/ \| DOMAIN_NAME:[^|]*/ /g')
        ad_to_send=$(echo "$ad_to_send" | sed -E 's/ \| ZIP_FILE:[^|]*/ /g')

        # Replace the " | " separator with a real newline for better Telegram formatting
        add_to_add="${ad_to_send// | /$'\n'}"
        full_message="${full_message}${add_to_add}"$'\n\n'
        send_info=1
        #echo "--> Sending to Telegram: $add_to_add"
        send_to_telegram "$add_to_add" "$TG_BOT_CHANNEL" "$ad_img"
        send_to_telegram "$add_to_add" "$TG_BOT_CHANNEL" "$ad_img" "$zip_file"
        #exit 1
        echo "$line_id" > $POSITIONS_FILE
        echo "Added to positions file: $line_id"
        rm -f "$zip_file"
    fi
done
