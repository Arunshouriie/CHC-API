from django.db import models

class trial(models.Model):
    Trial_name = models.CharField(max_length=25)
    Pharma_company = models.CharField(max_length=50)
    CRO = models.CharField(max_length=25)
    Trial_Id = models.IntegerField(default=-1)
    CRO_Trial_Id = models.IntegerField(default=-1)
    medication1_id = models.IntegerField(default=-1)
    medication2_id = models.IntegerField(default=-1)

    class Meta:
        verbose_name = "trial"
        verbose_name_plural = "trials"
