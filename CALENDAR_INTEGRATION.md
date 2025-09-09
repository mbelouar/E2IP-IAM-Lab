# Calendar Integration with Google Calendar

This document describes the calendar integration feature implemented in the SecureAuth Portal.

## Overview

The calendar application provides seamless integration with Google Calendar, allowing users to:

- View their Google Calendar directly within the portal
- Access full Google Calendar functionality
- Maintain secure authentication through the enterprise portal

## Features

### 1. Calendar View (`/calendar/`)

- **Embedded Google Calendar**: Displays the user's Google Calendar in an iframe
- **User Email Detection**: Automatically detects user email from SAML attributes or Django user profile
- **Responsive Design**: Works on desktop and mobile devices
- **Dark Mode Support**: Matches the portal's theme system

### 2. Google Calendar Redirect (`/calendar/google/`)

- **Direct Access**: Opens Google Calendar in a new tab
- **Full Functionality**: Access to all Google Calendar features
- **Activity Logging**: Tracks calendar access for security auditing

## Technical Implementation

### Backend Components

#### Views (`authentication/views.py`)

- `calendar_view()`: Main calendar page with embedded Google Calendar
- `google_calendar_redirect()`: Redirects to Google Calendar website

#### URL Patterns (`authentication/urls.py`)

```python
path('calendar/', views.calendar_view, name='calendar'),
path('calendar/google/', views.google_calendar_redirect, name='google_calendar_redirect'),
```

### Frontend Components

#### Calendar Template (`templates/authentication/calendar.html`)

- **Responsive Layout**: Adapts to different screen sizes
- **Google Calendar Embed**: Uses iframe to display calendar
- **Action Buttons**: Direct links to Google Calendar and back to dashboard
- **User Information**: Shows detected user email

#### Home Page Integration (`templates/authentication/home.html`)

- **Calendar App Icon**: Clickable calendar app in the applications grid
- **Navigation**: Direct link to calendar view

### Email Detection Logic

The system attempts to detect the user's email address in the following order:

1. **SAML Attributes**: Checks multiple SAML attribute keys:

   - `mail`
   - `email`
   - `userPrincipalName`
   - `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`
   - `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name`
   - `http://schemas.microsoft.com/ws/2008/06/identity/claims/emailaddress`
   - `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn`

2. **Django User Email**: Falls back to `request.user.email`

3. **Username Fallback**: Uses `{username}@gmail.com` as last resort

## Usage

### For Users

1. **Access Calendar**: Click the "Calendar" app in the "Your Applications" section
2. **View Calendar**: See your Google Calendar embedded in the portal
3. **Open Google Calendar**: Click "Open Google Calendar" for full functionality
4. **Return to Dashboard**: Use "Back to Dashboard" to return to the main portal

### For Administrators

1. **Monitor Access**: Calendar access is logged in the activity system
2. **Email Configuration**: Ensure SAML attributes include email information
3. **Security**: All calendar access goes through the same authentication system

## Security Features

- **Authentication Required**: All calendar views require user login
- **Activity Logging**: All calendar access is logged with timestamps and IP addresses
- **Secure Redirects**: Google Calendar opens in new tabs to maintain session security
- **Email Validation**: System validates and sanitizes email addresses

## Dependencies

The calendar integration requires the following packages (already added to `requirements.txt`):

```
google-api-python-client>=2.0.0
google-auth>=2.0.0
google-auth-oauthlib>=1.0.0
google-auth-httplib2>=0.1.0
```

## Configuration

### Environment Variables

No additional environment variables are required. The integration uses:

- User email from SAML attributes or Django user profile
- Standard Django authentication system
- Existing activity logging system

### Google Calendar Setup

Users need to:

1. Have a Google account with Calendar access
2. Ensure their email in the system matches their Google account email
3. Grant necessary permissions when prompted by Google

## Troubleshooting

### Common Issues

1. **Calendar Not Loading**:

   - Check if user email is correctly detected
   - Verify internet connection
   - Check browser console for iframe errors

2. **Email Detection Problems**:

   - Verify SAML attributes include email information
   - Check Django user profile has email set
   - Review activity logs for email detection attempts

3. **Permission Issues**:
   - Ensure user is logged in
   - Check if user has calendar access permissions
   - Verify Google account is properly configured

### Debug Information

The system logs the following information:

- Calendar access attempts
- Email detection process
- Google Calendar redirects
- Any errors during calendar loading

## Future Enhancements

Potential improvements for the calendar integration:

1. **Event Creation**: Allow creating events directly from the portal
2. **Calendar Sync**: Real-time synchronization with Google Calendar
3. **Multiple Calendars**: Support for multiple Google Calendar accounts
4. **Custom Styling**: More customization options for the embedded calendar
5. **Offline Support**: Basic offline calendar viewing capabilities

## Support

For technical support or questions about the calendar integration:

1. Check the activity logs for error details
2. Verify user email configuration
3. Test with different browsers and devices
4. Contact the system administrator for SAML configuration issues
