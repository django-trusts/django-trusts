from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('trusts_tests', '0006_trustee_team'),
    ]

    operations = [
        migrations.CreateModel(
            name='S1Account',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=40)),
            ],
        ),
        migrations.CreateModel(
            name='S1Organization',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=40)),
            ],
        ),
        migrations.CreateModel(
            name='S1Operation',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.CharField(max_length=40, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='S1Team',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=40)),
                ('members', models.ManyToManyField(blank=True, related_name='teams', to='trusts_tests.s1account')),
                ('organization', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='teams', to='trusts_tests.s1organization')),
            ],
        ),
        migrations.CreateModel(
            name='S1Bundle',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=40)),
                ('operations', models.ManyToManyField(blank=True, related_name='bundles', to='trusts_tests.s1operation')),
                ('team', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='bundles', to='trusts_tests.s1team')),
            ],
        ),
        migrations.CreateModel(
            name='S1Repository',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=40)),
                ('organization', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='repositories', to='trusts_tests.s1organization')),
            ],
        ),
        migrations.CreateModel(
            name='S1Issue',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=40)),
                ('repository', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='issues', to='trusts_tests.s1repository')),
            ],
        ),
        migrations.CreateModel(
            name='S1TeamGrant',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('operation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='team_grants', to='trusts_tests.s1operation')),
                ('repository', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='team_grants', to='trusts_tests.s1repository')),
                ('team', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='repo_grants', to='trusts_tests.s1team')),
            ],
            options={
                'unique_together': {('team', 'repository', 'operation')},
            },
        ),
        migrations.CreateModel(
            name='S1DirectGrant',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('account', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='repo_grants', to='trusts_tests.s1account')),
                ('operation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='direct_grants', to='trusts_tests.s1operation')),
                ('repository', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='direct_grants', to='trusts_tests.s1repository')),
            ],
            options={
                'unique_together': {('account', 'repository', 'operation')},
            },
        ),
        migrations.CreateModel(
            name='S1TrapGrant',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('operation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='trap_grants', to='trusts_tests.s1operation')),
                ('repository', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='trap_grants', to='trusts_tests.s1repository')),
                ('team', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='trap_grants', to='trusts_tests.s1team')),
            ],
        ),
        migrations.CreateModel(
            name='S1UnregisteredNote',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('text', models.CharField(default='', max_length=80)),
                ('repository', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notes', to='trusts_tests.s1repository')),
            ],
        ),
    ]
