# Meet Integration with Google Meet

This document describes the meet integration feature implemented in the SecureAuth Portal.

## Overview

The meet application provides seamless integration with Google Meet, allowing users to:

- Access Google Meet directly within the portal
- Start instant meetings, join with codes, and schedule meetings
- Access full Google Meet functionality including video calls, screen sharing, and recordings
- Maintain secure authentication through the enterprise portal

## Features

### 1. Meet View (`/meet/`)

- **Embedded Google Meet**: Displays Google Meet in an iframe
- **User Email Detection**: Automatically detects user email from SAML attributes or Django user profile
- **Quick Actions**: Interactive cards for common meeting tasks
- **Feature Showcase**: Highlights key Google Meet capabilities
- **Responsive Design**: Works on desktop and mobile devices
- **Dark Mode Support**: Matches the portal's theme system

### 2. Google Meet Redirect (`/meet/google/`)

- **Direct Access**: Opens Google Meet in a new tab
- **Full Functionality**: Access to all Google Meet features including:
  - HD video calls (up to 100 participants)
  - Screen sharing and presentation
  - Meeting recording and playback
  - Chat and messaging
  - Meeting scheduling
  - Breakout rooms
- **Activity Logging**: Tracks meet access for security auditing

## Technical Implementation

### Backend Components

#### Views (`authentication/views.py`)

- `meet_view()`: Main meet page with embedded Google Meet
- `google_meet_redirect()`: Redirects to Google Meet website

#### URL Patterns (`authentication/urls.py`)

```python
path('meet/', views.meet_view, name='meet'),
path('meet/google/', views.google_meet_redirect, name='google_meet_redirect'),
```

### Frontend Components

#### Meet Template (`templates/authentication/meet.html`)

- **Responsive Layout**: Adapts to different screen sizes
- **Google Meet Embed**: Uses iframe to display Google Meet
- **Quick Action Cards**: Interactive buttons for common tasks
- **Action Buttons**: Direct links to Google Meet and back to dashboard
- **User Information**: Shows detected user email
- **Feature Showcase**: Cards highlighting meet capabilities

#### Home Page Integration (`templates/authentication/home.html`)

- **Meet App Icon**: Clickable meet app in the applications grid
- **Navigation**: Direct link to meet view
- **Updated Icon**: Changed from users to video icon

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

1. **Access Meet**: Click the "Meet" app in the "Your Applications" section
2. **View Meet**: See Google Meet embedded in the portal
3. **Quick Actions**: Use the quick action cards for:
   - **New Meeting**: Start an instant meeting
   - **Join with Code**: Enter a meeting code to join
   - **Schedule Meeting**: Plan future meetings
   - **View Recordings**: Access meeting recordings
4. **Open Google Meet**: Click "Open Google Meet" for full functionality
5. **Return to Dashboard**: Use "Back to Dashboard" to return to the main portal

### For Administrators

1. **Monitor Access**: Meet access is logged in the activity system
2. **Email Configuration**: Ensure SAML attributes include email information
3. **Security**: All meet access goes through the same authentication system

## Key Features Highlighted

### 1. HD Video Calls

- High-quality video conferencing
- Support for up to 100 participants
- Adaptive quality based on connection

### 2. Audio & Screen Share

- Crystal clear audio quality
- Seamless screen sharing capabilities
- Presentation mode for better focus

### 3. Secure & Private

- Enterprise-grade security
- Encrypted communications
- Meeting room controls

### 4. Cross-Platform

- Works on desktop, mobile, and tablet
- Consistent experience across devices
- Easy access from anywhere

## Quick Actions

The meet page includes interactive quick action cards:

### 1. New Meeting

- **Function**: `createNewMeeting()`
- **Action**: Opens Google Meet with a new instant meeting
- **Use Case**: Start an immediate video call

### 2. Join with Code

- **Function**: `joinWithCode()`
- **Action**: Prompts for meeting code and joins the meeting
- **Use Case**: Join existing meetings using meeting codes

### 3. Schedule Meeting

- **Function**: `scheduleMeeting()`
- **Action**: Opens Google Calendar to schedule a meeting
- **Use Case**: Plan future meetings with calendar integration

### 4. View Recordings

- **Function**: `viewRecordings()`
- **Action**: Opens Google Drive to view meeting recordings
- **Use Case**: Access previously recorded meetings

## Security Features

- **Authentication Required**: All meet views require user login
- **Activity Logging**: All meet access is logged with timestamps and IP addresses
- **Secure Redirects**: Google Meet opens in new tabs to maintain session security
- **Email Validation**: System validates and sanitizes email addresses
- **Privacy Protection**: Meeting data is handled securely

## Dependencies

The meet integration uses the same Google API packages as other integrations:

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

### Google Meet Setup

Users need to:

1. Have a Google account with Meet access
2. Ensure their email in the system matches their Google account email
3. Grant necessary permissions when prompted by Google

## Troubleshooting

### Common Issues

1. **Meet Not Loading**:

   - Check if user email is correctly detected
   - Verify internet connection
   - Check browser console for iframe errors

2. **Email Detection Problems**:

   - Verify SAML attributes include email information
   - Check Django user profile has email set
   - Review activity logs for email detection attempts

3. **Permission Issues**:

   - Ensure user is logged in
   - Check if user has meet access permissions
   - Verify Google account is properly configured

4. **Quick Actions Not Working**:
   - Check browser popup blockers
   - Verify JavaScript is enabled
   - Check console for JavaScript errors

### Debug Information

The system logs the following information:

- Meet access attempts
- Email detection process
- Google Meet redirects
- Any errors during meet loading

## Differences from Other Integrations

While the Meet integration follows the same pattern as Calendar and Maps, there are some key differences:

1. **Interactive Quick Actions**: Includes JavaScript functions for common meeting tasks
2. **Meeting-Specific Features**: Focuses on video conferencing capabilities
3. **Icon Change**: Uses video icon instead of users icon
4. **Different Google Service**: Integrates with Google Meet instead of Calendar or Maps

## Future Enhancements

Potential improvements for the meet integration:

1. **Meeting History**: Display recent meetings and their status
2. **Custom Meeting Rooms**: Create organization-specific meeting rooms
3. **Meeting Analytics**: Track meeting usage and participation
4. **Integration with Calendar**: Direct calendar integration for meeting scheduling
5. **Custom Meeting Templates**: Pre-configured meeting settings
6. **Meeting Notifications**: Real-time notifications for upcoming meetings
7. **Recording Management**: Advanced recording organization and sharing
8. **Breakout Rooms**: Management of breakout room assignments

## Integration with Other Apps

The Meet app works seamlessly with other portal applications:

- **Calendar**: Can schedule meetings directly from calendar events
- **Documents**: Can share documents during meetings
- **Maps**: Can share locations for meeting venues
- **Mail**: Can send meeting invitations and follow-ups

## Best Practices

### For Users

1. **Test Audio/Video**: Check your camera and microphone before important meetings
2. **Use Good Lighting**: Ensure adequate lighting for video calls
3. **Stable Connection**: Use a stable internet connection for best quality
4. **Mute When Not Speaking**: Help reduce background noise
5. **Use Screen Share Wisely**: Only share necessary content

### For Administrators

1. **Monitor Usage**: Track meeting usage patterns
2. **Set Policies**: Establish meeting duration and participant limits
3. **Security Training**: Educate users on meeting security best practices
4. **Regular Updates**: Keep the integration updated with latest features

## Support

For technical support or questions about the meet integration:

1. Check the activity logs for error details
2. Verify user email configuration
3. Test with different browsers and devices
4. Contact the system administrator for SAML configuration issues
5. Check Google Meet service status for external issues
