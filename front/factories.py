# factories.py
import factory
from factory.django import DjangoModelFactory

from .models import Event

# Defining a factory


class EventFactory(DjangoModelFactory):
    class Meta:
        model = Event

    title = factory.Faker(
        "sentence",
        nb_words=5,
        variable_nb_words=True
    )


# Using a factory with auto-generated data
e = EventFactory()
e.user
e.categorye.title  # 51
e.text
