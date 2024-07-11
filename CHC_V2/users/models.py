from datetime import datetime
from email.policy import default
from operator import truediv
from tabnanny import verbose
from unittest.util import _MAX_LENGTH
import uuid
from django.db import models
from phonenumber_field.modelfields import PhoneNumberField

# Create your models here.
from django.dispatch import receiver
from django.urls import reverse
from django_rest_passwordreset.signals import reset_password_token_created
from django.core.mail import send_mail 


GENDER_CHOICES = (
        ('M', 'Male'),
        ('F', 'Female'),
    )
class Users(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.CharField(max_length=50)
    user_name = models.CharField(max_length=50)
    password = models.CharField(max_length=50)

    class Meta:
        verbose_name = "Users"
        verbose_name_plural = "Users"
    
    def __unicode__(self):
        return self.user_name

class Medicines(models.Model):
    name = models.CharField(max_length=100)
    user = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return self.name

class userinfo(models.Model):
    patient_id = models.IntegerField()
    # uuid = models.ForeignKey('User', on_delete=models.CASCADE)
    name = models.CharField(max_length=50, blank=True, null=True)
    dob = models.DateField(max_length=8, blank=True, null=True)
    trial_enrollment_date = models.DateField(max_length=8, blank=True, null=True)
    age = models.IntegerField()
    height = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)
    weight = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    address = models.CharField(max_length=250, blank=True, null=True)
    contact_no = PhoneNumberField(blank=True, help_text='Contact phone number')
    email = models.CharField(max_length=50, blank=True, null=True)
    nominee_name = models.CharField(max_length=50, blank=True, null=True)
    nominee_mobile = PhoneNumberField(blank=True, help_text='nominee phone number')
    postal_code = models.IntegerField(blank=True, null=True)
    state = models.CharField(max_length=50, blank=True, null=True, default= "")
    country = models.CharField(max_length=50, blank=True, null=True, default= "")
    current_clinician = models.CharField(max_length=50, blank=True, null=True, default= "")
    clinician_pic = models.ImageField(upload_to = 'images/', blank=True, default= "")
    diagnosis = models.CharField(max_length=250, blank=True, null=True, default= "")
    allergies = models.CharField(max_length=50, blank=True, null=True, default= "")
    medicine_name = models.CharField(max_length=50,  blank=True, null=True, default= "")
    medicine_pic = models.ImageField(upload_to = 'images/', default= "", blank=True)
    dose_duration = models.IntegerField(default=-1)
    dose_per_day = models.IntegerField(default=-1)
    dosage_time1 = models.TimeField(blank=True)
    dosage_time2 = models.TimeField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True, null=True)
    device_id = models.AutoField(primary_key=True, blank=True)

    class Meta:
        verbose_name = "User_profile"
        verbose_name_plural = "User_profiles"
    
    def __unicode__(self):
        return self.name

class SideEffect(models.Model):
    user = models.CharField(max_length=255)
    entry_time = models.DateTimeField(auto_now_add=True)
    side_effect = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.user.username} - {self.side_effect} at {self.entry_time}"


class Provisioning(models.Model):
    user_id = models.IntegerField()
    mac_id = models.CharField(max_length=25)
    public_ip = models.CharField(max_length=25)
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True, null=True)

    class Meta:
        verbose_name = "device"
        verbose_name_plural = "devices"

class Reminderschedulegroups(models.Model):
    duration_in_mins = models.IntegerField(default=-1)
    recurring = models.IntegerField(default=-1)
    No_of_alarms_before_dispense = models.IntegerField(default=-1)
    No_of_alarms_after_dispense = models.IntegerField(default=-1)
    time_range_between_alarms = models.CharField(max_length=50)
    text = models.BooleanField(default=False)
    class Meta:
        verbose_name = "Reminder_schedule"
        verbose_name_plural = "Reminders"
    
    def __unicode__(self):
        return self.duration_in_mins

class DispenseInfo(models.Model):
    # # uuid = models.ForeignKey('User', on_delete=models.CASCADE)
    # dispense_medicine = models.BooleanField(default = False)
    # time_stamp = models.DateTimeField(auto_now_add=True)
    id = models.AutoField(primary_key=True)
    schedule_id = models.IntegerField(default=-1)
    dispense_time = models.DateTimeField(default=datetime.now)
    alarms_start_time = models.DateTimeField(default=datetime.now)
    alarms_end_time = models.DateTimeField(default=datetime.now)
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True, null=True)

    class Meta:
        verbose_name = "Dispense"
        verbose_name_plural = "Dispense"

class ReminderSchedule_audit(models.Model):
    id = models.AutoField(primary_key=True)
    dispense_id = models.IntegerField(default=-1)
    dispense_consumed = models.BooleanField(default=False)
    date_of_alarms = models.DateTimeField(default=datetime.now)
    alarm_count = models.IntegerField(default=-1)

    class Meta:
        verbose_name = "Reminder_Audit_schedule"
        verbose_name_plural = "Reminder_Audits"

class AlarmAudit(models.Model):
    id = models.AutoField(primary_key=True)
    schedule_audit_id = models.IntegerField()
    alarm_number = models.IntegerField(default=-1)
    sent_time = models.IntegerField(default=-1)
    actual_time = models.IntegerField(default=-1)

    class Meta:
        verbose_name = "Alarm_Audit"
        verbose_name_plural = "Audits_Alarm"

class Dispense_Log(models.Model):
    dispense_id = models.AutoField(primary_key=True)
    medicine = models.ForeignKey(Medicines, on_delete=models.CASCADE)
    # user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    taken_on_time = models.BooleanField()
    dispense_time = models.DateTimeField(default=datetime.now)
    video_review = models.BooleanField(default=False)
    # points = models.DecimalField(blank=True, null=True, max_digits=12, decimal_places=3)
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True, null=True)
    reason_not_taken = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.medicine.name} - {self.dispense_time}"
    class Meta:
        verbose_name = "medicine_dispense"
        verbose_name_plural = "medicines"
    
class Points(models.Model):
    # user = models.ForeignKey(Users, on_delete=models.CASCADE)
    user = models.CharField(max_length=255)
    points = models.FloatField()
    dispense_log = models.OneToOneField(Dispense_Log, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.user.user_name} - {self.points}"

class Captureevent(models.Model):
    device_id = models.ForeignKey('Users', on_delete=models.CASCADE)
    menu_btn = models.DateTimeField(default=datetime.now)
    notification_btn = models.DateTimeField(default=datetime.now)
    home_btn = models.DateTimeField(default=datetime.now)
    dispense_btn = models.DateTimeField(default=datetime.now)
    reminder_btn = models.DateTimeField(default=datetime.now)
    travel_btn = models.DateTimeField(default=datetime.now)
    contact_btn = models.DateTimeField(default=datetime.now)
    sideeffect_btn = models.DateTimeField(default=datetime.now)
    setting_btn = models.DateTimeField(default=datetime.now)
    coaching_btn = models.DateTimeField(default=datetime.now)
    dose_schedule_btn = models.DateTimeField(default=datetime.now)
    reminder_group_btn = models.DateTimeField(default=datetime.now)
    med_review_btn = models.DateTimeField(default=datetime.now)
    profile_btn = models.DateTimeField(default=datetime.now)
    edit_profile_btn = models.DateTimeField(default=datetime.now)
    default_option_btn = models.DateTimeField(default=datetime.now)
    my_reminder_btn = models.DateTimeField(default=datetime.now)
    performance_btn = models.DateTimeField(default=datetime.now)
    learning_btn = models.DateTimeField(default=datetime.now)
    community_btn = models.DateTimeField(default=datetime.now)
    events_btn = models.DateTimeField(default=datetime.now)
    help_btn = models.DateTimeField(default=datetime.now)
    msg_template_btn = models.DateTimeField(default=datetime.now)
    msg_family_btn = models.DateTimeField(default=datetime.now)
    msg_clinical_btn = models.DateTimeField(default=datetime.now)
    msg_coherence_btn = models.DateTimeField(default=datetime.now)
    stop_recording_btn = models.DateTimeField(default=datetime.now)
    load_medication_btn = models.DateTimeField(default=datetime.now)
    more_menu_btn = models.DateTimeField(default=datetime.now)

    class Meta:
        verbose_name = "Capture_event"
        verbose_name_plural = "Capture_events"

class Trackerdata(models.Model):
    Broacasting_type = models.CharField(max_length=25, blank=True, null=True)
    Header_ID = models.CharField(max_length=25, blank=True, null=True)
    Blood_oxygen = models.CharField(max_length=25, blank=True, null=True)
    Stress_level = models.CharField(max_length=25, blank=True, null=True)
    RRI_HRV = models.CharField(max_length=25, blank=True, null=True)
    Activity_Intensity = models.CharField(max_length=25, blank=True, null=True)
    Blood_pressure_SBP = models.CharField(max_length=25, blank=True, null=True)
    Blood_pressure_DBP = models.CharField(max_length=25, blank=True, null=True)
    calorie = models.CharField(max_length=25, blank=True, null=True)
    surface_temperature = models.CharField(max_length=25, blank=True, null=True)
    body_temperature = models.CharField(max_length=25, blank=True, null=True)
    heart_rate = models.CharField(max_length=25, blank=True, null=True)
    sos = models.CharField(max_length=25, blank=True, null=True)
    battery = models.CharField(max_length=25, blank=True, null=True)
    beacon_battery = models.CharField(max_length=25, blank=True, null=True)
    Device_name = models.CharField(max_length=25, blank=True, null=True)
    Total = models.CharField(max_length=25, blank=True, null=True)


class Meta:
        verbose_name = "Tracker_data"
        verbose_name_plural = "Trackers_data"











@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):

    email_plaintext_message = "{}?token={}".format(reverse('password_reset:reset-password-request'), reset_password_token.key)

    send_mail(
        # title:
        "Password Reset for {title}".format(title="Some website title"),
        # message:
        email_plaintext_message,
        # from:
        "noreply@somehost.local",
        # to:
        [reset_password_token.user.email]
    )