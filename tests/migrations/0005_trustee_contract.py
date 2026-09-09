from django.db import migrations, models
import django.db.models.deletion
import trusts.trustee


class Migration(migrations.Migration):

    dependencies = [
        ('trusts_tests', '0004_context_contract'),
    ]

    operations = [
        migrations.CreateModel(
            name='TrusteeRequester',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=40)),
            ],
        ),
        migrations.CreateModel(
            name='TrusteeScope',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=40)),
            ],
        ),
        migrations.CreateModel(
            name='TrusteeOperation',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.CharField(max_length=40, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='TrusteeResource',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=40)),
                ('scope', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='resources', to='trusts_tests.trusteescope')),
            ],
        ),
        migrations.CreateModel(
            name='TrusteeCollective',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=40)),
                ('members', models.ManyToManyField(blank=True, related_name='collectives', to='trusts_tests.trusteerequester')),
                ('operations', models.ManyToManyField(blank=True, related_name='ceiling_collectives', to='trusts_tests.trusteeoperation')),
            ],
        ),
        migrations.CreateModel(
            name='TrusteeBundle',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=40, unique=True)),
                ('collectives', models.ManyToManyField(blank=True, related_name='bundles', to='trusts_tests.trusteecollective')),
                ('operations', models.ManyToManyField(blank=True, related_name='bundles', to='trusts_tests.trusteeoperation')),
            ],
            bases=(trusts.trustee.TrusteeMixin, models.Model),
        ),
        migrations.CreateModel(
            name='TrusteeDirectGrant',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('operation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='direct_grants', to='trusts_tests.trusteeoperation')),
                ('requester', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='direct_grants', to='trusts_tests.trusteerequester')),
                ('scope', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='direct_grants', to='trusts_tests.trusteescope')),
            ],
            options={
                'unique_together': {('scope', 'requester', 'operation')},
            },
        ),
        migrations.CreateModel(
            name='TrusteeCollectiveGrant',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('collective', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='grants', to='trusts_tests.trusteecollective')),
                ('operation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='collective_grants', to='trusts_tests.trusteeoperation')),
                ('scope', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='collective_grants', to='trusts_tests.trusteescope')),
            ],
            options={
                'unique_together': {('scope', 'collective', 'operation')},
            },
        ),
        migrations.CreateModel(
            name='TrusteeDesk',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=40)),
                ('collective', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='desks', to='trusts_tests.trusteecollective')),
            ],
        ),
        migrations.CreateModel(
            name='TrusteeDeskGrant',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('desk', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='grants', to='trusts_tests.trusteedesk')),
                ('operation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='desk_grants', to='trusts_tests.trusteeoperation')),
                ('scope', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='desk_grants', to='trusts_tests.trusteescope')),
            ],
        ),
        migrations.CreateModel(
            name='TrusteeTrapGrant',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('operation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='trap_grants', to='trusts_tests.trusteeoperation')),
                ('requester', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='trap_grants', to='trusts_tests.trusteerequester')),
                ('scope', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='trap_grants', to='trusts_tests.trusteescope')),
            ],
        ),
        migrations.CreateModel(
            name='UnregisteredTrusteeNote',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('text', models.CharField(default='', max_length=80)),
                ('scope', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notes', to='trusts_tests.trusteescope')),
            ],
        ),
    ]
