# Web Scraper with Telegram Notifications

A Bash script that scrapes ad listings from a website, extracts keywords, and sends notifications to Telegram channels. The script includes automatic session management, retry logic, and duplicate detection.

## Features

- 🔐 **Automatic Authentication**: Handles login with CSRF token extraction and session management
- 🔄 **Session Recovery**: Automatically re-authenticates when sessions expire
- 📊 **Keyword Extraction**: Extracts and analyzes keywords from ad listings
- 📱 **Telegram Integration**: Sends formatted messages with images to Telegram channels
- 🔁 **Retry Logic**: Automatic retries for failed requests (up to 3 attempts)
- 📝 **Progress Tracking**: Tracks processed ad IDs to avoid duplicates
- 🎯 **Multi-page Support**: Scrapes multiple pages of listings
- 🖼️ **Image Support**: Downloads and sends images with Telegram messages
- 🐛 **Debug Mode**: Optional debug output for troubleshooting

## Requirements

- Bash shell (works on Linux, macOS, and Windows with Git Bash/WSL)
- `curl` command-line tool
- `bsdtar` or compatible tar utility (for extracting ZIP files)
- `grep` with PCRE support (`-P` flag)
- `base64` utility
- Internet connection

### Windows Users

On Windows, the script automatically detects and uses `curl.exe` to avoid PowerShell alias conflicts.

## Installation

1. Clone or download this repository
2. Ensure all required utilities are installed
3. Make the script executable (Linux/macOS):
   ```bash
   chmod +x scrapper.sh
   ```

## Configuration

The script requires several parameters to be passed via command-line arguments:

### Required Parameters

- `-c <category>`: Category ID to scrape (default: 1)
- `-l <domain>`: Domain name of the target website (e.g., `example.com`)
- `-u <email>`: Login email address
- `-p <password>`: Login password
- `-t <token>`: Telegram bot token
- `-q <channel>`: Telegram channel ID or username

### Optional Parameters

- `-d`: Enable debug mode (shows detailed output)
- `-h`: Show help message

## Usage

### Basic Usage

```bash
./scrapper.sh -c 1 -l example.com -u your@email.com -p yourpassword -t YOUR_BOT_TOKEN -q @your_channel
```

### With Debug Mode

```bash
./scrapper.sh -c 1 -l example.com -u your@email.com -p yourpassword -t YOUR_BOT_TOKEN -q @your_channel -d
```

### Example

```bash
./scrapper.sh \
  -c 1 \
  -l ads.example.com \
  -u user@example.com \
  -p mypassword123 \
  -t 123456789:ABCdefGHIjklMNOpqrsTUVwxyz \
  -q @my_telegram_channel \
  -d
```

## How It Works

1. **Initialization**: Sets up temporary directories and files
2. **Authentication**: Logs into the website and saves session cookies
3. **Page Scraping**: Fetches ad listings from multiple pages (configurable via `MAX_PAGES_BACK`)
4. **ID Extraction**: Extracts ad IDs and structured data (description, image, country, date)
5. **Keyword Analysis**: Downloads ZIP files for each ad and extracts keywords
6. **Telegram Notifications**: 
   - Sends unique top keywords summary
   - Sends detailed ad information with images
7. **Progress Tracking**: Saves the highest processed ID to avoid reprocessing

## Configuration Variables

You can modify these variables in the script:

- `MAX_PAGES_BACK`: Number of pages to scrape (default: 2)
- `DELAY_SECONDS`: Delay between Telegram messages (default: 2)
- `MAX_ATTEMPTS`: Maximum retry attempts for failed requests (default: 3)
- `SKIP_KEYWORDS_LIST`: Keywords to skip when analyzing (e.g., 'Reply', 'Like', etc.)

## File Structure

```
.
├── scrapper.sh              # Main script
├── login_cookies.txt        # Saved session cookies (auto-generated)
├── temp/                    # Temporary files directory
│   ├── positions_*.txt     # Tracks last processed ID per category
│   └── page_response_*     # Temporary download files
└── README.md               # This file
```

## Telegram Bot Setup

1. Create a bot using [@BotFather](https://t.me/botfather) on Telegram
2. Get your bot token
3. Add the bot to your channel as an administrator
4. Get your channel ID (can be username like `@channel` or numeric ID)
5. Use these credentials in the script parameters

## Session Management

The script automatically:
- Saves cookies to `login_cookies.txt`
- Detects session expiration
- Re-authenticates when needed
- Retries failed requests with new session

## Error Handling

- **Session Expired**: Automatically re-authenticates and retries
- **Network Errors**: Retries up to 3 times with delays
- **Missing Data**: Skips problematic entries and continues
- **Invalid Responses**: Logs errors and continues processing

## Debug Mode

Enable debug mode with `-d` flag to see:
- All configuration values
- Detailed request/response information
- Extracted data at each step
- Telegram API responses

## Limitations

- Requires valid login credentials
- Depends on website structure (may break if HTML structure changes)
- Rate limiting: Includes delays to avoid overwhelming the server
- Windows compatibility: Uses `curl.exe` when available

## Troubleshooting

### Script fails to authenticate
- Verify your credentials are correct
- Check if the website structure has changed
- Enable debug mode to see detailed error messages

### No keywords found
- Check if the ZIP files are being downloaded correctly
- Verify HTML structure hasn't changed
- Enable debug mode to inspect downloaded content

### Telegram messages not sending
- Verify bot token is correct
- Ensure bot is added to channel as admin
- Check channel ID/username format
- Enable debug mode to see API responses

### Session keeps expiring
- The script should auto-recover, but if issues persist:
- Delete `login_cookies.txt` and restart
- Check if website has additional security measures

## Security Notes

- **Never commit** `login_cookies.txt` to version control
- Store credentials securely (consider using environment variables)
- The script includes `login_cookies.txt` and `temp/` in `.gitignore`

## License

This script is provided as-is for educational and personal use.

## Contributing

Feel free to submit issues or pull requests for improvements.

## Support

For issues or questions, please check:
1. Debug mode output (`-d` flag)
2. Error messages in console
3. Temporary files in `temp/` directory
