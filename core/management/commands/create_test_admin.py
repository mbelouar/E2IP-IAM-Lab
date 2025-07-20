from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.db import IntegrityError

class Command(BaseCommand):
    help = 'Creates a test admin user for development purposes'

    def add_arguments(self, parser):
        parser.add_argument('--username', default='admin', help='Admin username')
        parser.add_argument('--password', default='admin123', help='Admin password')
        parser.add_argument('--email', default='admin@example.com', help='Admin email')

    def handle(self, *args, **options):
        username = options['username']
        password = options['password']
        email = options['email']
        
        self.stdout.write(f"Creating test admin user: {username}")
        
        try:
            user = User.objects.create_superuser(
                username=username,
                email=email,
                password=password,
                first_name='Admin',
                last_name='User'
            )
            self.stdout.write(self.style.SUCCESS(f"Successfully created admin user: {user.username}"))
        except IntegrityError:
            self.stdout.write(self.style.WARNING(f"User {username} already exists"))
            user = User.objects.get(username=username)
            user.is_staff = True
            user.is_superuser = True
            user.email = email
            user.set_password(password)
            user.save()
            self.stdout.write(self.style.SUCCESS(f"Updated existing user: {user.username}"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error creating admin user: {e}"))
