from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('trusts_tests', '0003_receipt'),
    ]

    operations = [
        migrations.CreateModel(
            name='ContextScope',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=40)),
            ],
        ),
        migrations.CreateModel(
            name='ContextDocument',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=40)),
                ('scope', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='documents', to='trusts_tests.contextscope')),
            ],
        ),
        migrations.CreateModel(
            name='ContextAttachment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('caption', models.CharField(default='', max_length=80)),
                ('document', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='attachments', to='trusts_tests.contextdocument')),
            ],
        ),
        migrations.CreateModel(
            name='ContextAnnotation',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('note', models.CharField(default='', max_length=80)),
                ('attachment', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='annotations', to='trusts_tests.contextattachment')),
            ],
        ),
        migrations.CreateModel(
            name='ContextTrap',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scope', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='traps', to='trusts_tests.contextscope')),
            ],
        ),
    ]
