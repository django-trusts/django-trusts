from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Account',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=40)),
            ],
        ),
        migrations.CreateModel(
            name='Operation',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.CharField(max_length=40, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='Organization',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=40)),
            ],
        ),
        migrations.CreateModel(
            name='Policy',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=40)),
            ],
        ),
        migrations.CreateModel(
            name='Team',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=40)),
                ('members', models.ManyToManyField(blank=True, related_name='teams', to='gh_vocab.account')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='teams', to='gh_vocab.organization')),
            ],
        ),
        migrations.CreateModel(
            name='PermissionBundle',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=40)),
                ('operations', models.ManyToManyField(blank=True, related_name='bundles', to='gh_vocab.operation')),
                ('team', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='permission_bundles', to='gh_vocab.team')),
            ],
        ),
        migrations.CreateModel(
            name='Repository',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=40)),
                ('policy', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='repositories', to='gh_vocab.policy')),
            ],
        ),
        migrations.CreateModel(
            name='TeamPolicyGrant',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('operation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='team_grants', to='gh_vocab.operation')),
                ('policy', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='team_grants', to='gh_vocab.policy')),
                ('team', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='policy_grants', to='gh_vocab.team')),
            ],
            options={
                'unique_together': {('policy', 'team', 'operation')},
            },
        ),
        migrations.CreateModel(
            name='GhTrapGrant',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('operation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='trap_grants', to='gh_vocab.operation')),
                ('policy', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='trap_grants', to='gh_vocab.policy')),
                ('team', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='trap_grants', to='gh_vocab.team')),
            ],
        ),
        migrations.CreateModel(
            name='UnregisteredGhNote',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('text', models.CharField(default='', max_length=80)),
                ('repository', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notes', to='gh_vocab.repository')),
            ],
        ),
    ]
