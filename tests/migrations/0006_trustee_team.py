from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('auth', '0012_alter_user_first_name_max_length'),
        ('trusts', '0002_trustgroup'),
        ('trusts_tests', '0005_trustee_contract'),
    ]

    operations = [
        migrations.CreateModel(
            name='TrusteeTeam',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=40)),
                ('members', models.ManyToManyField(blank=True, related_name='trustee_teams', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='TrusteeTeamGrant',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('permission', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='trustee_team_grants', to='auth.permission')),
                ('team', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='grants', to='trusts_tests.trusteeteam')),
                ('trust', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='trustee_team_grants', to='trusts.trust')),
            ],
            options={
                'unique_together': {('trust', 'team', 'permission')},
            },
        ),
    ]
