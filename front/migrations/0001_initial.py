# Generated by Django 4.1.7 on 2024-03-03 12:21

from django.conf import settings
import django.contrib.gis.db.models.fields
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import front.models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='MyUser',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('id', models.AutoField(db_index=True, primary_key=True, serialize=False)),
                ('username', models.CharField(db_index=True, max_length=200, unique=True)),
                ('email', models.EmailField(db_index=True, max_length=255, unique=True, verbose_name='email address')),
                ('first_name', models.CharField(max_length=200)),
                ('last_name', models.CharField(max_length=200)),
                ('bank_number', models.CharField(blank=True, max_length=26, validators=[django.core.validators.MaxLengthValidator(26), django.core.validators.MinLengthValidator(26)])),
                ('is_active', models.BooleanField(default=True)),
                ('is_admin', models.BooleanField(default=False)),
                ('is_verificated', models.BooleanField(db_index=True, default=False)),
                ('is_banned', models.BooleanField(db_index=True, default=False)),
                ('image', models.ImageField(default='default/user_images/default.png', upload_to='user_images')),
                ('image_thumbnail', models.ImageField(blank=True, default='default/user_thumbnails/default_thumbnail.png', upload_to='user_thumbnails')),
                ('distance', models.IntegerField(default=100)),
                ('count_reported_events', models.IntegerField(default=0)),
                ('count_reported_badges', models.IntegerField(default=0)),
                ('count_reported_comments', models.IntegerField(default=0)),
                ('count_deleted_events', models.IntegerField(default=0)),
                ('count_deleted_badges', models.IntegerField(default=0)),
                ('count_deleted_comments', models.IntegerField(default=0)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Badge',
            fields=[
                ('id', models.AutoField(db_index=True, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=50)),
                ('image', models.ImageField(upload_to='badge_image')),
                ('verificated', models.CharField(choices=[('verificated', 'Zweryfikowane'), ('awaiting', 'Oczekujące na akceptacje'), ('need_improvement', 'Wymagane poprawy przez organizatora'), ('rejected', 'Odrzucone')], default='verificated', max_length=36)),
                ('verificated_details', models.TextField(blank=True, default=None, null=True)),
                ('created_time', models.DateField(default=django.utils.timezone.now, editable=False)),
                ('edit_time', models.DateTimeField(default=django.utils.timezone.now)),
                ('to_remove', models.BooleanField(default=False)),
                ('creator', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='created_badges', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.AutoField(db_index=True, primary_key=True, serialize=False)),
                ('type', models.CharField(max_length=50)),
                ('details', models.CharField(max_length=200)),
                ('image', models.ImageField(upload_to='category_img/')),
            ],
        ),
        migrations.CreateModel(
            name='City',
            fields=[
                ('name', models.CharField(max_length=100)),
                ('id', models.CharField(db_index=True, max_length=10, primary_key=True, serialize=False)),
                ('geo_location', django.contrib.gis.db.models.fields.PointField(blank=True, db_index=True, null=True, srid=4326)),
            ],
        ),
        migrations.CreateModel(
            name='DeleteModel',
            fields=[
                ('id', models.IntegerField(db_index=True, primary_key=True, serialize=False)),
                ('content_type', models.CharField(choices=[('MyUser', 'Użytkownik'), ('IPAddress', 'Adres IP'), ('Event', 'Wydarzenie'), ('CommentEvent', 'Komentarz'), ('Badge', 'Odznaka'), ('Ticket', 'Bilet'), ('Order', 'Zamówienie'), ('AwaitingsTicketsRefund', 'Zwrot pieniędzy'), {'GatewayPaycheck', 'Przyznany przelew'}], max_length=100)),
                ('ids_array', models.TextField(default='[]')),
            ],
        ),
        migrations.CreateModel(
            name='Event',
            fields=[
                ('id', models.AutoField(db_index=True, primary_key=True, serialize=False)),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False)),
                ('title', models.CharField(max_length=200)),
                ('text', models.TextField()),
                ('created_time', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('edit_time', models.DateTimeField(default=django.utils.timezone.now)),
                ('slug', models.SlugField(editable=False)),
                ('event_date', models.DateField()),
                ('schedule', models.TextField()),
                ('verificated', models.CharField(choices=[('verificated', 'Zweryfikowane'), ('awaiting', 'Oczekujące na akceptacje'), ('need_improvement', 'Wymagane poprawy przez organizatora'), ('rejected', 'Odrzucone')], default='verificated', max_length=36)),
                ('verificated_details', models.TextField(blank=True, default=None, max_length=150, null=True)),
                ('to_remove', models.BooleanField(default=False)),
                ('allow_paycheck', models.BooleanField(default=False)),
                ('to_start_refund', models.BooleanField(default=False)),
                ('rejected_time', models.DateTimeField(blank=True, null=True)),
                ('category', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='front.category')),
                ('city', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='front.city')),
            ],
        ),
        migrations.CreateModel(
            name='IPAddress',
            fields=[
                ('id', models.AutoField(db_index=True, primary_key=True, serialize=False)),
                ('ip_address', models.CharField(db_index=True, max_length=30)),
                ('is_banned', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.IntegerField(db_index=True, primary_key=True, serialize=False)),
                ('content_type', models.CharField(choices=[('MyUser', 'Użytkownik'), ('IPAddress', 'Adres IP'), ('Event', 'Wydarzenie'), ('CommentEvent', 'Komentarz'), ('Badge', 'Odznaka'), ('Ticket', 'Bilet'), ('Order', 'Zamówienie'), ('AwaitingsTicketsRefund', 'Zwrot pieniędzy'), {'GatewayPaycheck', 'Przyznany przelew'}], max_length=100)),
                ('text', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='Order',
            fields=[
                ('id', models.BigAutoField(db_index=True, primary_key=True, serialize=False)),
                ('stripe_payment_intent_id', models.CharField(max_length=255)),
                ('checkout_payment_intent_id', models.CharField(blank=True, max_length=100)),
                ('orderedtickets_ids_array', models.TextField(default='[]')),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('stripe_created_at', models.DateTimeField(blank=True, null=True)),
                ('order_expires_at', models.DateTimeField(blank=True, null=True)),
                ('next_try_at', models.DateTimeField(blank=True, null=True)),
                ('paid_time', models.DateTimeField(blank=True, null=True)),
                ('is_paid', models.BooleanField(default=False)),
                ('to_remove', models.BooleanField(default=False)),
                ('user', models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='OrderedTicket',
            fields=[
                ('id', models.BigAutoField(db_index=True, primary_key=True, serialize=False)),
                ('purchase_price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('first_name', models.CharField(max_length=200)),
                ('last_name', models.CharField(max_length=200)),
                ('date_of_birth', models.DateField()),
                ('code', models.UUIDField(null=True)),
                ('qr_code', models.ImageField(upload_to='qrcodes/')),
                ('used', models.BooleanField(default=False)),
                ('used_time', models.DateTimeField(blank=True, null=True)),
                ('refunded', models.BooleanField(default=False)),
                ('order', models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, related_name='ordered_tickets', to='front.order')),
            ],
        ),
        migrations.CreateModel(
            name='Province',
            fields=[
                ('id', models.CharField(db_index=True, max_length=3, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='FacebookUser',
            fields=[
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL)),
                ('social_id', models.CharField(db_index=True, max_length=100, unique=True)),
                ('first_name', models.CharField(max_length=200)),
                ('last_name', models.CharField(max_length=200)),
                ('image', models.ImageField(upload_to='facebook_images')),
            ],
        ),
        migrations.CreateModel(
            name='GmailUser',
            fields=[
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL)),
                ('social_id', models.CharField(db_index=True, max_length=100, unique=True)),
                ('first_name', models.CharField(max_length=200)),
                ('last_name', models.CharField(max_length=200)),
                ('image', models.ImageField(upload_to='gmail_images')),
            ],
        ),
        migrations.CreateModel(
            name='Ticket',
            fields=[
                ('id', models.BigAutoField(db_index=True, primary_key=True, serialize=False)),
                ('stripe_id', models.CharField(blank=True, max_length=255)),
                ('stripe_name_product', models.CharField(blank=True, max_length=255)),
                ('ticket_type', models.CharField(max_length=255)),
                ('ticket_details', models.TextField()),
                ('default_price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('new_price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('quantity', models.PositiveIntegerField()),
                ('verificated', models.CharField(choices=[('verificated', 'Zweryfikowane'), ('awaiting', 'Oczekujące na akceptacje'), ('need_improvement', 'Wymagane poprawy przez organizatora'), ('rejected', 'Odrzucone')], default='awaiting', max_length=36)),
                ('verificated_details', models.TextField(blank=True, default=None, max_length=150, null=True)),
                ('was_allowed', models.BooleanField(default=False)),
                ('to_remove', models.BooleanField(default=False)),
                ('edit_time', models.DateTimeField(default=django.utils.timezone.now)),
                ('event', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='tickets_of_event', to='front.event')),
            ],
        ),
        migrations.CreateModel(
            name='Series',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('description', models.CharField(max_length=200)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Paycheck',
            fields=[
                ('id', models.BigAutoField(db_index=True, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('stripe_refund_checkout_mode', models.BooleanField(default=False)),
                ('refund_confirmation', models.FileField(blank=True, null=True, upload_to='payment_confirmation/')),
                ('bank_number', models.CharField(blank=True, max_length=26, validators=[django.core.validators.MaxLengthValidator(26), django.core.validators.MinLengthValidator(26)])),
                ('event', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='front.event')),
                ('tickets', models.ManyToManyField(blank=True, db_index=True, to='front.orderedticket')),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='user_paychecks', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddField(
            model_name='orderedticket',
            name='ticket',
            field=models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, related_name='orders_of_tickets', to='front.ticket'),
        ),
        migrations.CreateModel(
            name='NotificationsForUser',
            fields=[
                ('id', models.BigAutoField(db_index=True, primary_key=True, serialize=False)),
                ('notifications_array', models.TextField(default='[]')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='user_notifications', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='IPAddressValidator',
            fields=[
                ('id', models.AutoField(db_index=True, primary_key=True, serialize=False)),
                ('is_verificated', models.BooleanField(db_index=True, default=False)),
                ('last_login_time', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('name_device', models.CharField(blank=True, max_length=200, null=True)),
                ('ip_address', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='users_of_ip', to='front.ipaddress')),
                ('last_login_city', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='front.city')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='validators_of_user', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('user', 'ip_address')},
            },
        ),
        migrations.CreateModel(
            name='GatewayPaycheck',
            fields=[
                ('id', models.BigAutoField(db_index=True, primary_key=True, serialize=False)),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('stage_to_remove', models.BooleanField(default=False)),
                ('remove_time', models.DateTimeField(blank=True, null=True)),
                ('created_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='user_gateways', to=settings.AUTH_USER_MODEL)),
                ('event', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='front.event')),
                ('paycheck', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='front.paycheck')),
                ('tickets', models.ManyToManyField(blank=True, db_index=True, to='front.orderedticket')),
            ],
        ),
        migrations.CreateModel(
            name='EventImage',
            fields=[
                ('id', models.AutoField(db_index=True, primary_key=True, serialize=False)),
                ('image', models.ImageField(upload_to='event_img/')),
                ('image_thumbnail', models.ImageField(blank=True, upload_to='event_thumbnails/')),
                ('order', models.IntegerField(default=0)),
                ('main', models.BooleanField(db_index=True, default=False)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('event', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='images', to='front.event')),
            ],
        ),
        migrations.AddField(
            model_name='event',
            name='series',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='events_for_series', to='front.series'),
        ),
        migrations.AddField(
            model_name='event',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='created_events', to=settings.AUTH_USER_MODEL),
        ),
        migrations.CreateModel(
            name='CustomOutstandingToken',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('jti', models.CharField(max_length=255, unique=True)),
                ('token', models.TextField()),
                ('created_at', models.DateTimeField(blank=True, null=True)),
                ('expires_at', models.DateTimeField()),
                ('ip_validator', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='refresh_tokens_of_validator', to='front.ipaddressvalidator')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ('user',),
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='CustomBlacklistedToken',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('blacklisted_at', models.DateTimeField(auto_now_add=True)),
                ('token', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='front.customoutstandingtoken')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='County',
            fields=[
                ('id', models.CharField(db_index=True, max_length=3, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('province', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='front.province')),
            ],
        ),
        migrations.CreateModel(
            name='CommentEvent',
            fields=[
                ('id', models.AutoField(db_index=True, primary_key=True, serialize=False)),
                ('text', models.TextField(max_length=500)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('score', models.IntegerField(default=0)),
                ('reported_details', models.TextField(blank=True, default=None, max_length=150, null=True)),
                ('is_blocked', models.BooleanField(default=False)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='created_comments', to=settings.AUTH_USER_MODEL)),
                ('event', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='event', to='front.event')),
                ('parent_comment', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='replies', to='front.commentevent')),
            ],
        ),
        migrations.CreateModel(
            name='CodeRegistration',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code_random', models.CharField(blank=True, max_length=6, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddField(
            model_name='city',
            name='county',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='front.county'),
        ),
        migrations.CreateModel(
            name='ChangeEmailWaiting',
            fields=[
                ('id', models.BigAutoField(db_index=True, primary_key=True, serialize=False)),
                ('code_random', models.CharField(blank=True, max_length=6, null=True)),
                ('email', models.EmailField(db_index=True, max_length=255, verbose_name='email address')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='BadgeCode',
            fields=[
                ('id', models.AutoField(db_index=True, primary_key=True, serialize=False)),
                ('code', models.CharField(db_index=True, default=front.models.generate_unique_code, max_length=24, unique=True)),
                ('status', models.CharField(choices=[('c) used', 'Użyto'), ('b) locked', 'Zarezerwowano'), ('a) to_use', 'Do użycia')], default='a) to_use', max_length=20)),
                ('created_time', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('activated_time', models.DateTimeField(blank=True, null=True)),
                ('activated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('badge', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='front.badge')),
            ],
        ),
        migrations.AddField(
            model_name='badge',
            name='event',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='front.event'),
        ),
        migrations.CreateModel(
            name='AwaitingsTicketsRefund',
            fields=[
                ('id', models.BigAutoField(db_index=True, primary_key=True, serialize=False)),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10, null=True)),
                ('tickets', models.ManyToManyField(blank=True, db_index=True, to='front.orderedticket')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='AdminLog',
            fields=[
                ('id', models.BigAutoField(db_index=True, primary_key=True, serialize=False)),
                ('action_time', models.DateTimeField(default=django.utils.timezone.now)),
                ('action_flag', models.CharField(choices=[('confirmation', 'Zatwierdzenie'), ('deletion', 'Usuwanie'), ('to_improvement', 'Przekazanie do poprawy'), ('clear', 'Oczyszczone ze zgłoszeń'), ('ban_user', 'Banowanie użytkownika'), ('ban_ip', 'Banowanie adresu IP'), ('logout', 'Wylogowywanie'), ('paycheck', 'Wypłata środków')], max_length=36)),
                ('content_type', models.CharField(choices=[('MyUser', 'Użytkownik'), ('IPAddress', 'Adres IP'), ('IPAddressValidator', 'Uwierzytelniacz'), ('Event', 'Wydarzenie'), ('CommentEvent', 'Komentarz'), ('Badge', 'Odznaka'), ('Ticket', 'Bilet'), ('GatewayPaycheck', 'Bramka płatności')], max_length=100)),
                ('id_content_type', models.IntegerField(blank=True, default=None)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='ActiveMessage',
            fields=[
                ('message_id', models.AutoField(db_index=True, primary_key=True, serialize=False)),
                ('content', models.TextField()),
                ('timestamp', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('is_delivered', models.BooleanField(default=False)),
                ('is_seen', models.BooleanField(default=False)),
                ('recipient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='received_messages', to=settings.AUTH_USER_MODEL)),
                ('sender', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sent_messages', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddField(
            model_name='myuser',
            name='activated_badges',
            field=models.ManyToManyField(blank=True, related_name='badge_owners', to='front.badge'),
        ),
        migrations.AddField(
            model_name='myuser',
            name='blocked_users',
            field=models.ManyToManyField(blank=True, related_name='blocked_by', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='myuser',
            name='city',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='front.city'),
        ),
        migrations.AddField(
            model_name='myuser',
            name='friends',
            field=models.ManyToManyField(blank=True, related_name='friends_list', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='myuser',
            name='ip_validator',
            field=models.ManyToManyField(through='front.IPAddressValidator', to='front.ipaddress'),
        ),
        migrations.AddField(
            model_name='myuser',
            name='main_badge',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='users_with_main_badge', to='front.badge'),
        ),
        migrations.AddField(
            model_name='myuser',
            name='take_part_events',
            field=models.ManyToManyField(blank=True, related_name='participants_event', to='front.event'),
        ),
        migrations.AddField(
            model_name='myuser',
            name='visited_events',
            field=models.ManyToManyField(blank=True, related_name='visitors_event', to='front.event'),
        ),
        migrations.CreateModel(
            name='Friendship_Request',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('from_user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='from_user', to=settings.AUTH_USER_MODEL)),
                ('to_user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='to_user', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('from_user', 'to_user')},
            },
        ),
        migrations.CreateModel(
            name='EventReport',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_time', models.DateTimeField(default=django.utils.timezone.now)),
                ('details', models.TextField(blank=True, default=None, max_length=150, null=True)),
                ('type', models.CharField(choices=[('Naruszenie regulaminu', 'Naruszenie regulaminu'), ('Dyskryminacja', 'Dyskryminacja'), ('Fałszywe informacje', 'Fałszywe informacje'), ('Niezgodność z zasadami społeczności', 'Niezgodność z zasadami społeczności'), ('Niewłaściwe zachowanie organizatora', 'Niewłaściwe zachowanie organizatora'), ('Propagowanie nielegalnych działań', 'Propagowanie nielegalnych działań')], max_length=47)),
                ('event', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='front.event')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('event', 'user')},
            },
        ),
        migrations.CreateModel(
            name='CommentEventReport',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_time', models.DateTimeField(default=django.utils.timezone.now)),
                ('details', models.TextField(blank=True, default=None, max_length=150, null=True)),
                ('type', models.CharField(choices=[('Treści reklamowe lub spam', 'Treści reklamowe lub spam'), ('Materiały erotyczne i pornograficzne', 'Materiały erotyczne i pornograficzne'), ('Wykorzystywanie dzieci', 'Wykorzystywanie dzieci'), ('Propagowanie terroryzmu', 'Propagowanie terroryzmu'), ('Nękanie lub dokuczanie', 'Nękanie lub dokuczanie'), ('Nieprawdziwe informacje', 'Nieprawdziwe informacje')], max_length=47)),
                ('comment', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='front.commentevent')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('comment', 'user')},
            },
        ),
        migrations.CreateModel(
            name='CommentEventReaction',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(choices=[('Like', 'Like'), ('Dislike', 'Dislike'), ('Delete', 'Delete')], max_length=8)),
                ('comment', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='front.commentevent')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('comment', 'user')},
            },
        ),
        migrations.CreateModel(
            name='BadgeReport',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_time', models.DateTimeField(default=django.utils.timezone.now)),
                ('details', models.TextField(blank=True, default=None, max_length=150, null=True)),
                ('type', models.CharField(choices=[('Naruszenie regulaminu', 'Naruszenie regulaminu'), ('Dyskryminacja', 'Dyskryminacja'), ('Fałszywe informacje', 'Fałszywe informacje'), ('Niezgodność z zasadami społeczności', 'Niezgodność z zasadami społeczności'), ('Obraźliwa miniaturka', 'Obraźliwa miniaturka'), ('Propagowanie nielegalnych działań', 'Propagowanie nielegalnych działań')], max_length=47)),
                ('badge', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='front.badge')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('badge', 'user')},
            },
        ),
    ]