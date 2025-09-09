# Maps Integration with Google Maps

This document describes the maps integration feature implemented in the SecureAuth Portal.

## Overview

The maps application provides seamless integration with Google Maps, allowing users to:

- View Google Maps directly within the portal
- Access full Google Maps functionality including navigation, search, and location services
- Maintain secure authentication through the enterprise portal

## Features

### 1. Maps View (`/maps/`)

- **Embedded Google Maps**: Displays Google Maps in an iframe with a default location (Empire State Building)
- **User Email Detection**: Automatically detects user email from SAML attributes or Django user profile
- **Responsive Design**: Works on desktop and mobile devices
- **Dark Mode Support**: Matches the portal's theme system
- **Feature Cards**: Highlights key Google Maps capabilities

### 2. Google Maps Redirect (`/maps/google/`)

- **Direct Access**: Opens Google Maps in a new tab
- **Full Functionality**: Access to all Google Maps features including:
  - Search and navigation
  - Real-time traffic updates
  - Street View
  - Location sharing
  - Route planning
- **Activity Logging**: Tracks maps access for security auditing

## Technical Implementation

### Backend Components

#### Views (`authentication/views.py`)

- `maps_view()`: Main maps page with embedded Google Maps
- `google_maps_redirect()`: Redirects to Google Maps website

#### URL Patterns (`authentication/urls.py`)

```python
path('maps/', views.maps_view, name='maps'),
path('maps/google/', views.google_maps_redirect, name='google_maps_redirect'),
```

### Frontend Components

#### Maps Template (`templates/authentication/maps.html`)

- **Responsive Layout**: Adapts to different screen sizes
- **Google Maps Embed**: Uses iframe to display maps
- **Action Buttons**: Direct links to Google Maps and back to dashboard
- **User Information**: Shows detected user email
- **Feature Showcase**: Cards highlighting maps capabilities

#### Home Page Integration (`templates/authentication/home.html`)

- **Maps App Icon**: Clickable maps app in the applications grid
- **Navigation**: Direct link to maps view
- **Updated Icon**: Changed from chart-line to map-marked-alt

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

1. **Access Maps**: Click the "Maps" app in the "Your Applications" section
2. **View Maps**: See Google Maps embedded in the portal with default location
3. **Open Google Maps**: Click "Open Google Maps" for full functionality including:
   - Search for places
   - Get directions
   - View real-time traffic
   - Access Street View
   - Share locations
4. **Return to Dashboard**: Use "Back to Dashboard" to return to the main portal

### For Administrators

1. **Monitor Access**: Maps access is logged in the activity system
2. **Email Configuration**: Ensure SAML attributes include email information
3. **Security**: All maps access goes through the same authentication system

## Key Features Highlighted

### 1. Search & Navigation

- Find places worldwide
- Get turn-by-turn directions
- Explore locations with detailed information

### 2. Real-time Traffic

- Live traffic updates
- Optimal route suggestions
- Traffic incident alerts

### 3. Location Services

- Share your current location
- Discover nearby places
- Save favorite locations

### 4. Street View

- 360-degree street-level imagery
- Virtual exploration of locations
- Historical imagery comparison

## Security Features

- **Authentication Required**: All maps views require user login
- **Activity Logging**: All maps access is logged with timestamps and IP addresses
- **Secure Redirects**: Google Maps opens in new tabs to maintain session security
- **Email Validation**: System validates and sanitizes email addresses
- **Privacy Protection**: Location data is handled securely

## Dependencies

The maps integration uses the same Google API packages as the calendar integration:

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

### Google Maps Setup

Users need to:

1. Have a Google account with Maps access
2. Ensure their email in the system matches their Google account email
3. Grant necessary permissions when prompted by Google

## Troubleshooting

### Common Issues

1. **Maps Not Loading**:

   - Check if user email is correctly detected
   - Verify internet connection
   - Check browser console for iframe errors

2. **Email Detection Problems**:

   - Verify SAML attributes include email information
   - Check Django user profile has email set
   - Review activity logs for email detection attempts

3. **Permission Issues**:
   - Ensure user is logged in
   - Check if user has maps access permissions
   - Verify Google account is properly configured

### Debug Information

The system logs the following information:

- Maps access attempts
- Email detection process
- Google Maps redirects
- Any errors during maps loading

## Differences from Calendar Integration

While the Maps integration follows the same pattern as the Calendar integration, there are some key differences:

1. **Default Location**: Maps shows Empire State Building by default instead of user-specific calendar
2. **Feature Showcase**: Includes feature cards highlighting maps capabilities
3. **Icon Change**: Uses map-marked-alt icon instead of chart-line
4. **Different Google Service**: Integrates with Google Maps instead of Google Calendar

## Future Enhancements

Potential improvements for the maps integration:

1. **Custom Default Location**: Allow setting organization-specific default locations
2. **Location History**: Track and display user location history
3. **Geofencing**: Set up location-based alerts and notifications
4. **Custom Markers**: Add organization-specific map markers
5. **Offline Maps**: Basic offline map viewing capabilities
6. **Route Optimization**: Advanced route planning for multiple stops
7. **Location Sharing**: Real-time location sharing between team members

## Support

For technical support or questions about the maps integration:

1. Check the activity logs for error details
2. Verify user email configuration
3. Test with different browsers and devices
4. Contact the system administrator for SAML configuration issues

## Integration with Other Apps

The Maps app works seamlessly with other portal applications:

- **Calendar**: Can be used to plan travel time for events
- **Documents**: Can be used to locate document-related addresses
- **Teams**: Can be used for team meeting locations
- **Mail**: Can be used to find email-related addresses
