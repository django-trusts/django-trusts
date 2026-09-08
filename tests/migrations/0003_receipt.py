from django.db import migrations, models
import django.db.models.deletion
import trusts.models


class Migration(migrations.Migration):

    dependencies = [
        ('trusts_tests', '0002_ticket'),
    ]

    operations = [
        migrations.CreateModel(
            name='Receipt',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=40)),
                ('trust', models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, related_name='trusts_tests_receipt_content', to='trusts.trust')),
            ],
            options={
                'default_permissions': ('add', 'read', 'change', 'delete'),
            },
            bases=(trusts.models.ReadonlyFieldsMixin, models.Model),
        ),
        migrations.CreateModel(
            name='ReceiptImage',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('caption', models.CharField(default='', max_length=80)),
                ('receipt', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='image', to='trusts_tests.receipt')),
            ],
            options={
                'default_permissions': ('add', 'read', 'change', 'delete'),
            },
        ),
        migrations.CreateModel(
            name='ReceiptImageMeta',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('note', models.CharField(default='', max_length=80)),
                ('image', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='meta', to='trusts_tests.receiptimage')),
            ],
            options={
                'default_permissions': ('add', 'read', 'change', 'delete'),
            },
        ),
        migrations.CreateModel(
            name='UnregisteredReceiptNote',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('text', models.CharField(default='', max_length=80)),
                ('receipt', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notes', to='trusts_tests.receipt')),
            ],
            options={
                'default_permissions': ('add', 'read', 'change', 'delete'),
            },
        ),
    ]
