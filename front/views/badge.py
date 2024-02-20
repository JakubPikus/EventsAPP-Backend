from rest_framework.views import APIView
from rest_framework import permissions, status
from rest_framework.response import Response
from ..serializers import EventsViaBadgesSerializer, BadgesCodesListSerializer, BadgesCodesCreateSerializer, BadgeCodesReturnedUsedSerializer, BadgeEditSerializer, BadgeCreateSerializer, BadgeDeleteSerializer, UserBadgesActivatedSerializer, UserBadgesCreatedSerializer, BadgeActivateSerializer, BadgeReportSerializer
from ..models import Event, EventImage, Badge, BadgeCode, BadgeReport
from .functions import token_verify
from django.db.models import OuterRef, F, Q, Func, Subquery
from django.db.models.functions import JSONObject
from django.contrib.postgres.expressions import ArraySubquery
from django.utils import timezone
import ast


class EventsViaBadgesView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = EventsViaBadgesSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                user = request.user
                time_now = timezone.now()
                ordering = request.GET.get('ordering', 'created_time')

                if ordering == "created_time" or ordering == "status":

                    if ordering == "created_time":
                        order_by_settings = ["-created_time", "status"]
                    else:
                        order_by_settings = ["status", "-created_time"]

                    subquery_main_image = EventImage.objects.filter(
                        event=OuterRef('pk'), main=True).values('image_thumbnail')

                    #############

                    subquery_badge_codes = BadgeCode.objects.filter(
                        badge__pk=OuterRef('pk')).annotate(data=JSONObject(id=F('id'), code=F('code'), status=F('status'), activated_by=F('activated_by__username'), created_time=F('created_time'))).order_by(*order_by_settings).values('data')

                    subquery_badge_codes_to_use_count = BadgeCode.objects.filter(
                        badge__pk=OuterRef('pk'), status="a) to_use").annotate(count=Func(F('id'), function='Count')).values('count')

                    subquery_badge_codes_locked_count = BadgeCode.objects.filter(
                        badge__pk=OuterRef('pk'), status="b) locked").annotate(count=Func(F('id'), function='Count')).values('count')

                    subquery_badge_codes_used_count = BadgeCode.objects.filter(
                        badge__pk=OuterRef('pk'), status="c) used").annotate(count=Func(F('id'), function='Count')).values('count')

                    subquery_badges = Badge.objects.filter(
                        event__pk=OuterRef('pk')).annotate(data=JSONObject(id=F('id'), name=F('name'), image=F('image'), verificated=F('verificated'), verificated_details=F('verificated_details'), codes=ArraySubquery(subquery_badge_codes), used_codes_count=Subquery(subquery_badge_codes_used_count), to_use_codes_count=Subquery(subquery_badge_codes_to_use_count), locked_codes_count=Subquery(subquery_badge_codes_locked_count))).values('data')

                    #############

                    events = Event.objects.select_related('category', 'city').filter(
                        user=user, event_date__gte=time_now).annotate(province=F('city__county__province__name'), image=Subquery(subquery_main_image), badges=ArraySubquery(subquery_badges)).order_by('event_date')

                    events = EventsViaBadgesSerializer(events, many=True)

                    return Response(
                        {'success': 'Pobrano wydarzenia', 'data': events.data,
                            "code": "7667"},
                        status=status.HTTP_200_OK
                    )
                else:
                    return Response(
                        {'detail': 'Jako wartość "ordering" akceptowane jest tylko "created_time" lub "is_active".',
                         "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BadgeCodesLockedToExportView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgesCodesListSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                event_id = data['event_id']
                badge_id = data['badge_id']
                badge_codes_id_list = data['badge_codes_id_list']
                user = request.user
                if event_id != "":
                    if badge_id != "":
                        if badge_codes_id_list != "":
                            if not isinstance(badge_codes_id_list, list):
                                try:
                                    literal_eval_badge_codes_id_list = ast.literal_eval(
                                        badge_codes_id_list)

                                    set_badge_codes_id_list = set(
                                        literal_eval_badge_codes_id_list)
                                except:
                                    return Response(
                                        {'detail': 'Przesyłana wartość w "badge_codes_id_list" musi mieć format list z liczbami określającymi ID kodów aktywacyjnych do rezerwacji.',
                                            "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                set_badge_codes_id_list = set(
                                    badge_codes_id_list)

                            if Event.objects.filter(id=event_id).exists():
                                event = Event.objects.get(id=event_id)
                                if event.user == user:

                                    if Badge.objects.filter(event=event, id=badge_id).exists():
                                        badge = Badge.objects.get(
                                            event=event, id=badge_id)

                                        if not badge.verificated == "rejected":

                                            if BadgeCode.objects.filter(badge=badge, id__in=set_badge_codes_id_list).exists():
                                                badge_codes = BadgeCode.objects.filter(
                                                    badge=badge, id__in=set_badge_codes_id_list)

                                                if badge_codes.count() == len(set_badge_codes_id_list):

                                                    if all(badge_code.status == "a) to_use" for badge_code in badge_codes):

                                                        badge_codes.update(
                                                            status="b) locked")

                                                        badge_codes = BadgesCodesListSerializer(
                                                            badge_codes, many=True)

                                                        return Response(
                                                            {'success': 'Sukces', 'locked_codes': {'data': badge_codes.data, 'id_list': set_badge_codes_id_list, 'append_data': None}, 'used_codes': {'data': None, 'id_list': None},
                                                                "code": "1500"},
                                                            status=status.HTTP_200_OK
                                                        )
                                                    elif not any(badge_code.status == "b) locked" for badge_code in badge_codes):

                                                        # NAMIERZENIE NIEUŻYTYCH KODÓW Z TYCH PODANYCH ORAZ ZMIANA ICH STANU NA LOCKED

                                                        not_used_badge_codes = badge_codes.filter(
                                                            Q(activated_by=None))
                                                        not_used_badge_codes.update(
                                                            status="b) locked")

                                                        # NAMIERZENIE UŻYTYCH KODÓW Z TYCH PODANYCH

                                                        used_badge_codes = badge_codes.select_related(
                                                            'activated_by').filter(~Q(activated_by=None))

                                                        # USTALENIE TYCH ID, KTÓRE ZOSTAŁY UŻYTE DO : 1) USUNIĘCIA Z LISTY PODANYCH ID TYCH, KTORE ZOSTAŁY ZUŻYTE; 2) ABY POINFORMOWAĆ REDUCER O ZMIANIE STANU ZUŻYTYCH KODÓW NA "used" AKTYWOWANE PRZEZ x_user
                                                        used_ids = set(
                                                            used_badge_codes.values_list('id', flat=True))

                                                        # USUNIĘCIE TYCH ID KODÓW Z LISTY KTÓRA ZOSTAŁA WYSŁANA DO LOCKOWANIA, KTÓRE WCZEŚNIEJ ZOSTAŁY AKTYWOWANE, ABY ZWRÓCIĆ DO REDUCERA LISTĘ ID DO ZMIANY STANU NA "locked" a nie "used"
                                                        set_badge_codes_id_list -= used_ids

                                                        # UTWORZENIE NOWYCH KODÓW ZE STATUSEM "b) locked" W TAKIEJ ILOŚCI, ILE KODÓW ZOSTAŁO WYKRYTE JAKO UŻYTE
                                                        new_badge_codes = [
                                                            BadgeCode(badge=badge, status="b) locked") for _ in range(len(used_ids))]

                                                        created_badge_codes = BadgeCode.objects.bulk_create(
                                                            new_badge_codes)

                                                        # UZYSKANIE ID UTWORZONYCH OBIEKTÓW TAK, ABY PRZEKSZTAŁCIĆ W QUERYSET PRZED WYKONANIEM "union"
                                                        created_ids = [
                                                            obj.pk for obj in created_badge_codes]

                                                        # POBRANIE QUERYSET UTWORZONYCH OBIEKTÓW
                                                        created_badge_codes_queryset = BadgeCode.objects.filter(
                                                            pk__in=created_ids)

                                                        # SERIALIZACJA UTWORZONYCH KODÓW DO DODANIA DO REDUCERA
                                                        created_badge_codes_serialized = BadgesCodesCreateSerializer(
                                                            created_badge_codes, many=True)

                                                        # POŁĄCZENIE ZE SOBĄ DLA EXPORTU KODÓW:
                                                        #
                                                        # 1) KODY PODANE KTÓRE NIE SĄ UŻYTE
                                                        #
                                                        # 2) KODY UTWORZONE W ILOŚCI TAKIEJ, ILE WYKRYTO UŻYTYCH

                                                        codes_to_export = not_used_badge_codes.union(
                                                            created_badge_codes_queryset)

                                                        # SERIALIZACJA ZSUMOWANYCH KODÓW DO EXPORTU DO POPRAWNEGO ODBIORU PRZEZ GENERATOR EXCEL

                                                        codes_to_export = BadgesCodesListSerializer(
                                                            codes_to_export, many=True)

                                                        # SERIALIZACJA WCZEŚNIEJ UŻYTYCH KODÓW DO POWIADOMIENIA UŻYTKOWNIKA W MODALU O ZMIANIE
                                                        used_badge_codes = BadgeCodesReturnedUsedSerializer(
                                                            used_badge_codes, many=True)

                                                        return Response(
                                                            {'success': 'Sukces', 'locked_codes': {'data': codes_to_export.data, 'id_list': set_badge_codes_id_list, 'append_data': created_badge_codes_serialized.data}, 'used_codes': {"data": used_badge_codes.data, "id_list": used_ids},
                                                                "code": "1500"},
                                                            status=status.HTTP_200_OK
                                                        )

                                                    else:

                                                        return Response(
                                                            {'detail': 'Nie można przekazywać kodu do rezerwacji, który już wcześniej został zarezerwowany.',
                                                             "code": "9011"},
                                                            status=status.HTTP_400_BAD_REQUEST
                                                        )
                                                else:
                                                    return Response(
                                                        {'detail': 'Przynajmniej jeden z twoich przekazywanych ID kodu aktywacyjnego nie istnieje w tej odznace.',
                                                         "code": "9011"},
                                                        status=status.HTTP_400_BAD_REQUEST
                                                    )
                                            else:
                                                return Response(
                                                    {'detail': 'Żaden z twoich przekazywanych ID kodu aktywacyjnego nie istnieje w tej odznace.',
                                                     "code": "9011"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )
                                        else:
                                            return Response(
                                                {'detail': 'Odznaka jest odrzucona.', 'status': {"verificated": badge.verificated, "details": badge.verificated_details},
                                                 "code": "1511"},
                                                status=223
                                            )
                                    else:
                                        return Response(
                                            {'detail': 'Taka odznaka nie istnieje.',
                                             "code": "1512"},
                                            status=222
                                        )
                                else:
                                    return Response(
                                        {'detail': 'Te wydarzenie nie należy do Ciebie.',
                                         "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': 'Nie ma takiego wydarzenia z takim ID.',
                                     "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': 'Musisz podać przynajmniej listę jednoelementową z ID kodu aktywacyjnego.',
                                 "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Nie podano ID odznaki.',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie podano ID wydarzenia',
                         "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BadgeCodesCreateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgesCodesCreateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                event_id = data['event_id']
                badge_id = data['badge_id']
                amount = data['amount']
                user = request.user

                if event_id != "":
                    if badge_id != "":
                        if str(amount).isdigit() and int(amount) > 0 and int(amount) <= 100:

                            if Event.objects.filter(id=event_id).exists():
                                event = Event.objects.get(id=event_id)
                                if event.user == user:

                                    if Badge.objects.filter(event=event, id=badge_id).exists():
                                        badge = Badge.objects.get(
                                            event=event, id=badge_id)

                                        if not badge.verificated == "rejected":

                                            badge_codes = [
                                                BadgeCode(badge=badge) for _ in range(int(amount))]

                                            created_badge_codes = BadgeCode.objects.bulk_create(
                                                badge_codes)

                                            created_badge_codes = BadgesCodesCreateSerializer(
                                                created_badge_codes, many=True)

                                            return Response(
                                                {'success': 'Sukces', 'data': created_badge_codes.data,
                                                    "code": "1501"},
                                                status=status.HTTP_200_OK
                                            )
                                        else:
                                            return Response(
                                                {'detail': 'Odznaka jest odrzucona.', 'status': {"verificated": badge.verificated, "details": badge.verificated_details},
                                                 "code": "1511"},
                                                status=223
                                            )
                                    else:
                                        return Response(
                                            {'detail': 'Taka odznaka nie istnieje.',
                                             "code": "1512"},
                                            status=222
                                        )
                                else:
                                    return Response(
                                        {'detail': 'Te wydarzenie nie należy do Ciebie.',
                                         "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': 'Nie ma takiego wydarzenia z takim ID.',
                                     "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': 'Musisz podać ilość nowych kodów (minimum 1).',
                                    "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Nie podano ID odznaki.',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie podano ID wydarzenia',
                         "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BadgeCodesDeleteView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgesCodesListSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                event_id = data['event_id']
                badge_id = data['badge_id']
                badge_codes_id_list = data['badge_codes_id_list']
                user = request.user
                if event_id != "":
                    if badge_id != "":
                        if badge_codes_id_list != "":
                            if not isinstance(badge_codes_id_list, list):
                                try:
                                    literal_eval_badge_codes_id_list = ast.literal_eval(
                                        badge_codes_id_list)

                                    set_badge_codes_id_list = set(
                                        literal_eval_badge_codes_id_list)
                                except:
                                    return Response(
                                        {'detail': 'Przesyłana wartość w "badge_codes_id_list" musi mieć format list z liczbami określającymi ID kodów aktywacyjnych do rezerwacji.',
                                            "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                set_badge_codes_id_list = set(
                                    badge_codes_id_list)

                            if Event.objects.filter(id=event_id).exists():
                                event = Event.objects.get(id=event_id)
                                if event.user == user:

                                    if Badge.objects.filter(event=event, id=badge_id).exists():
                                        badge = Badge.objects.get(
                                            event=event, id=badge_id)

                                        if not badge.verificated == "rejected":

                                            if BadgeCode.objects.filter(badge=badge, id__in=set_badge_codes_id_list).exists():
                                                badge_codes = BadgeCode.objects.filter(
                                                    badge=badge, id__in=set_badge_codes_id_list)

                                                if badge_codes.count() == len(set_badge_codes_id_list):

                                                    if all(badge_code.status == "a) to_use" for badge_code in badge_codes):

                                                        badge_codes.delete()

                                                        return Response(
                                                            {'success': 'Sukces', 'deleted_codes': {'data': None, 'id_list': set_badge_codes_id_list}, 'used_codes': {"data": None, "id_list": None},
                                                                "code": "1502"},
                                                            status=status.HTTP_200_OK
                                                        )

                                                    elif not any(badge_code.status == "b) locked" for badge_code in badge_codes):

                                                        # NAMIERZENIE NIEUŻYTYCH KODÓW Z TYCH PODANYCH ORAZ USUNIĘCIE ICH

                                                        not_used_badge_codes = badge_codes.filter(
                                                            Q(activated_by=None))

                                                        deleted_codes = BadgeCodesReturnedUsedSerializer(
                                                            not_used_badge_codes, many=True).data

                                                        not_used_badge_codes.delete()

                                                        # NAMIERZENIE UŻYTYCH KODÓW Z TYCH PODANYCH

                                                        used_badge_codes = badge_codes.select_related(
                                                            'activated_by').filter(~Q(activated_by=None))

                                                        # USTALENIE TYCH ID, KTÓRE ZOSTAŁY UŻYTE DO : 1) USUNIĘCIA Z LISTY PODANYCH ID TYCH, KTORE ZOSTAŁY ZUŻYTE; 2) ABY POINFORMOWAĆ REDUCER O ZMIANIE STANU ZUŻYTYCH KODÓW NA "used" AKTYWOWANE PRZEZ x_user
                                                        used_ids = set(
                                                            used_badge_codes.values_list('id', flat=True))

                                                        # USUNIĘCIE TYCH ID KODÓW Z LISTY KTÓRA ZOSTAŁA WYSŁANA DO USUNIĘCIA, KTÓRE WCZEŚNIEJ ZOSTAŁY AKTYWOWANE, ABY ZWRÓCIĆ DO REDUCERA LISTĘ ID USUNIĘTYCH KODÓW
                                                        set_badge_codes_id_list -= used_ids

                                                        # SERIALIZACJA WCZEŚNIEJ UŻYTYCH KODÓW DO POWIADOMIENIA UŻYTKOWNIKA W MODALU O ZMIANIE ICH STANU
                                                        used_badge_codes = BadgeCodesReturnedUsedSerializer(
                                                            used_badge_codes, many=True)

                                                        return Response(
                                                            {'success': 'Sukces', 'deleted_codes': {'data': deleted_codes, 'id_list': set_badge_codes_id_list}, 'used_codes': {"data": used_badge_codes.data, "id_list": used_ids},
                                                                "code": "1502"},
                                                            status=status.HTTP_200_OK
                                                        )

                                                    else:
                                                        return Response(
                                                            {'detail': 'Nie można przekazywać kodu do usunięcia, który już wcześniej został zarezerwowany.',
                                                             "code": "9011"},
                                                            status=status.HTTP_400_BAD_REQUEST
                                                        )
                                                else:
                                                    return Response(
                                                        {'detail': 'Przynajmniej jeden z twoich przekazywanych ID kodu aktywacyjnego nie istnieje w tej odznace.',
                                                         "code": "9011"},
                                                        status=status.HTTP_400_BAD_REQUEST
                                                    )
                                            else:
                                                return Response(
                                                    {'detail': 'Żaden z twoich przekazywanych ID kodu aktywacyjnego nie istnieje w tej odznace.',
                                                     "code": "9011"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )
                                        else:
                                            return Response(
                                                {'detail': 'Odznaka jest odrzucona.', 'status': {"verificated": badge.verificated, "details": badge.verificated_details},
                                                 "code": "1511"},
                                                status=223
                                            )
                                    else:
                                        return Response(
                                            {'detail': 'Taka odznaka nie istnieje.',
                                             "code": "1512"},
                                            status=222
                                        )
                                else:
                                    return Response(
                                        {'detail': 'Te wydarzenie nie należy do Ciebie.',
                                         "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': 'Nie ma takiego wydarzenia z takim ID.',
                                     "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': 'Musisz podać przynajmniej listę jednoelementową z ID kodu aktywacyjnego.',
                                 "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Nie podano ID odznaki.',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie podano ID wydarzenia',
                         "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BadgeEditView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgeEditSerializer

    def image_check(self, image, name, badge_name, badge_image):

        if isinstance(image, str):

            if image == "" and name == badge_name:

                return Response(
                    {'detail': 'Twoja edycja musi wprowadzać przynajmniej zmianę nazwy w momencie, kiedy nie chcesz zmieniać obrazka.',
                        "code": "9011"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            else:
                return Response(
                    {'detail': 'Próbujesz przesłać string w miejsce zdjęcia. Musisz podać dokładny odnośnik starego zdjęcia, aby pozostało ono przypisane do odznaki.',
                        "code": "9011"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        elif image and image.content_type not in ['image/jpeg', 'image/png', 'image/gif']:
            return Response(
                {'detail': 'Przesyłane zdjęcie nie jest plikiem graficznym.',
                    "code": "9011"},
                status=status.HTTP_400_BAD_REQUEST
            )

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                badge_id = data['badge_id']
                name = data['name']
                image = data['image']
                user = request.user

                if badge_id != "":
                    if name != "":
                        if len(name) >= 5 and len(name) <= 50:
                            if Badge.objects.filter(id=badge_id).exists():
                                badge = Badge.objects.get(id=badge_id)

                                if not badge.verificated == "rejected":

                                    if not Badge.objects.filter(name=name).exists() or badge.name == name:

                                        if badge.creator == user:

                                            if not badge.name == name or not badge.image == image:

                                                # if badge.edit_time

                                                diffrence_time = int(
                                                    (timezone.now() - badge.edit_time).total_seconds())

                                                if diffrence_time > 180:

                                                    filter_save = {}
                                                    if badge.image != image:
                                                        self.image_check(
                                                            image, name, badge.name, badge.image)
                                                        badge.image = image
                                                    else:
                                                        filter_save["generate_thumbnail"] = False

                                                    badge.name = name

                                                    if user.is_admin:
                                                        badge.verificated = "verificated"
                                                        code = "1504"
                                                    else:
                                                        badge.verificated = "awaiting"
                                                        code = "1503"
                                                    badge.save(**filter_save)

                                                    return Response(
                                                        {'success': 'Sukces', 'status': badge.verificated, 'image': badge.image.name, 'name': badge.name,
                                                         "code": code},
                                                        status=status.HTTP_200_OK
                                                    )
                                                else:

                                                    minutes = diffrence_time // 60
                                                    seconds = diffrence_time % 60

                                                    if minutes == 0:
                                                        response = f'Minęło dopiero {seconds} sekund.'

                                                    elif minutes == 1:
                                                        response = f'Minęła dopiero {minutes} minuta i {seconds} sekund.'

                                                    else:
                                                        response = f'Minęły dopiero {minutes} minuty i {seconds} sekund.'

                                                    return Response(
                                                        {'detail': response,
                                                         "code": "1513"},
                                                        status=status.HTTP_400_BAD_REQUEST
                                                    )

                                            else:
                                                return Response(
                                                    {'detail': 'Bez zmian.',
                                                     "code": "1505"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )
                                        else:
                                            return Response(
                                                {'detail': 'Podana odznaka nie należy do wydarzenia stworzonego przez tego użytkownika.',
                                                 "code": "9011"},
                                                status=status.HTTP_400_BAD_REQUEST
                                            )

                                    else:
                                        return Response(
                                            {'detail': 'Istnieje już odznaka z taką nazwą',
                                             "code": "1510"},
                                            status=status.HTTP_400_BAD_REQUEST
                                        )
                                else:
                                    return Response(
                                        {'detail': 'Odznaka jest odrzucona.', 'status': {"verificated": badge.verificated, "details": badge.verificated_details},
                                         "code": "1511"},
                                        status=223
                                    )

                            else:
                                return Response(
                                    {'detail': 'Taka odznaka nie istnieje.',
                                     "code": "1512"},
                                    status=222
                                )
                        else:
                            return Response(
                                {'detail': 'Nazwa odznaki musi posiadać minimum 5 znaków i maksymalnie 50 znaków.',
                                 "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Nie podano nazwy odznaki.',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Nie podano ID odznaki.',
                         "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BadgeCreateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgeCreateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                event_id = data['event_id']
                name = data['name']
                image = data['image']
                user = request.user

                if event_id != "":
                    if name != "":
                        if len(name) >= 5 and len(name) <= 50:
                            if not Badge.objects.filter(name=name).exists():

                                if Event.objects.filter(id=event_id).exists():
                                    event = Event.objects.get(id=event_id)

                                    if event.user == user:

                                        if image != "":

                                            if image.content_type in ['image/jpeg', 'image/png', 'image/gif']:

                                                badge = Badge(
                                                    event=event, creator=user, name=name, image=image)

                                                if user.is_admin:
                                                    badge.verificated = "verificated"
                                                    code = "1507"
                                                else:
                                                    badge.verificated = "awaiting"
                                                    code = "1506"
                                                badge.save()

                                                badge = BadgeCreateSerializer(
                                                    badge)

                                                return Response(
                                                    {'success': 'Sukces', 'data': badge.data,
                                                        "code": code},
                                                    status=status.HTTP_200_OK
                                                )

                                            else:

                                                return Response(
                                                    {'detail': 'Przesyłane zdjęcie nie jest plikiem graficznym.',
                                                     "code": "9011"},
                                                    status=status.HTTP_400_BAD_REQUEST
                                                )
                                        else:

                                            return Response(
                                                {'detail': 'Nie możesz utworzyć odznaki bez przesłania obrazka.',
                                                 "code": "9011"},
                                                status=status.HTTP_400_BAD_REQUEST
                                            )

                                    else:
                                        return Response(
                                            {'detail': 'Podane ID wydarzenia nie należy do tego użytkownika.',
                                             "code": "9011"},
                                            status=status.HTTP_400_BAD_REQUEST
                                        )
                                else:
                                    return Response(
                                        {'detail': 'Nie istnieje takie wydarzenie z podanym ID.',
                                         "code": "9011"},
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                            else:
                                return Response(
                                    {'detail': 'Istnieje już odznaka z taką nazwą',
                                     "code": "1510"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )
                        else:
                            return Response(
                                {'detail': 'Nazwa odznaki musi posiadać minimum 5 znaków i maksymalnie 50 znaków.',
                                 "code": "9011"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        return Response(
                            {'detail': 'Nie podano nazwy odznaki.',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Nie podano ID wydarzenia.',
                         "code": "9011"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BadgeDeleteView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgeDeleteSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                badge_id = data['badge_id']
                user = request.user

                if Badge.objects.filter(id=badge_id).exists():
                    badge = Badge.objects.get(id=badge_id)
                    if badge.creator == user:

                        badge.delete()

                        return Response(
                            {'success': 'Sukces',
                             "code": "1508"},
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            {'detail': 'Odznaka przypisana jest nie do wydarzenia utworzonego przez tego użytkownika.',
                             "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Nie istnieje odznaka z takim ID.',
                            "code": "1512"},
                        status=222
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UserBadgesView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = UserBadgesActivatedSerializer

    def get(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:

                user = request.user

                filter_activated_badges = {}
                if not user.is_admin:
                    filter_activated_badges["verificated"] = "verificated"

                subquery_activated_time = BadgeCode.objects.filter(
                    badge__pk=OuterRef('pk'), activated_by=user
                ).values('activated_time')[:1]

                subquery_report_type = BadgeReport.objects.filter(
                    badge__pk=OuterRef('pk'), user=user
                ).values('type')[:1]

                activated_badges = user.activated_badges.select_related(
                    'event').filter(**filter_activated_badges).annotate(slug_event=F('event__slug'), uuid_event=F('event__uuid'), activated_time=Subquery(subquery_activated_time), my_report=Subquery(subquery_report_type)).order_by('-id')

                created_badges = Badge.objects.filter(creator=user).select_related(
                    'event', 'creator').annotate(slug_event=F('event__slug'), uuid_event=F('event__uuid'))

                activated_badges = UserBadgesActivatedSerializer(
                    activated_badges, many=True)

                created_badges = UserBadgesCreatedSerializer(
                    created_badges, many=True)

                return Response(
                    {'success': 'Pobrano wydarzenia', 'created_badges': created_badges.data, 'activated_badges': activated_badges.data,
                        "code": "7667"},
                    status=status.HTTP_200_OK
                )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BadgeActivateView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgeActivateSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                code = data['code']
                user = request.user

                if BadgeCode.objects.filter(code__iexact=code).exists():
                    badge_code = BadgeCode.objects.get(code__iexact=code)

                    if badge_code.badge.creator != user:

                        # GDY KOD DO ODZNAKI NIE ZOSTAŁ UŻYTY
                        if badge_code.status != "c) used":

                            # GDY ODZNAKA ANI RAZU NIE BYŁA AKTYWOWANA PRZEZ USERA
                            if not user.activated_badges.filter(id=badge_code.badge.id).exists():
                                if badge_code.badge.verificated == "verificated":  # GDY JEST ZWERYFIKOWANA, NASTĘPUJE PRZYPISANIE

                                    if user.main_badge == None:
                                        set_main_badge = True
                                        user.main_badge = badge_code.badge
                                        user.save(generate_thumbnail=False)

                                    else:
                                        set_main_badge = False

                                    success_response = 'Sukces'
                                    status_response = status.HTTP_200_OK
                                    only_title = False
                                elif badge_code.badge.verificated == "rejected":

                                    success_response = 'Odznaka, którą próbujesz aktywować została usunięta przez portal z powodu naruszeń regulaminu. Niestety, ale ta odznaka nie zostanie przypisana do twojego konta do odwołania, a kod zostanie usunięty. Gdy odznaka zostanie przywrócona, dostaniesz powiadomienie, a odznaka zostanie przypisana do konta.'
                                    status_response = 223
                                    only_title = True
                                    set_main_badge = False

                                elif badge_code.badge.verificated == "awaiting":

                                    success_response = 'Kod jest poprawny, ale odznaka nie przeszła jeszcze weryfikacji, a jej status to "oczekujący". Gdy odznaka zostanie zweryfikowana, dostaniesz powiadomienie, a odznaka zostanie przypisana do konta.'
                                    status_response = 223
                                    only_title = True
                                    set_main_badge = False

                                else:  # TUTAJ GDY ADMIN TO "BADGET", JAK USER TO "TITLE_EVENT"
                                    success_response = 'Kod jest poprawny, ale odznaka nie przeszła jeszcze weryfikacji, a jej status to "wymaga zmian". Gdy odznaka zostanie zweryfikowana, dostaniesz powiadomienie, a odznaka zostanie przypisana do konta.'
                                    status_response = 223
                                    only_title = True
                                    set_main_badge = False

                                badge_code.badge.badge_owners.add(user)
                                badge_code.status = "c) used"
                                badge_code.activated_by = user
                                badge_code.save()
                                was_activated = False

                            #  GDY ODZNAKA BYŁA AKTYWOWANA, ALE MOŻE MIEĆ DOWOLNY STAN:
                            else:

                                set_main_badge = False

                                # GDY USER/ADMIN PROBUJE AKTYWOWAC ODZNAKE, KTÓRĄ JUZ MA I JEST "ZWERYFIKOWANA"
                                if badge_code.badge.verificated == "verificated":
                                    only_title = False
                                    success_response = 'Ta odznaka jest już aktualnie przypisana do twojego konta.'

                                # GDY USER/ADMIN PROBUJE AKTYWOWAC ODZNAKE, KTÓRĄ JUZ MA, ALE JEST DO "USUNIĘCIA"
                                elif badge_code.badge.verificated == "rejected":
                                    only_title = True
                                    success_response = 'Posiadasz już tą odznakę, ale jej status to "do usunięcia".'

                                # GDY USER/ADMIN PROBUJE AKTYWOWAC ODZNAKE, KTÓRĄ JUZ MA, ALE JEST DO "USUNIĘCIA"
                                elif badge_code.badge.verificated == "awaiting":
                                    only_title = True
                                    success_response = 'Posiadasz już tą odznakę, ale jej status to "oczekujący na akceptację".'

                                else:  # GDY USER/ADMIN PROBUJE AKTYWOWAC ODZNAKE, KTÓRĄ JUZ MA, ALE JEST DO "ZWERYFIKOWANIA"
                                    only_title = True
                                    success_response = 'Posiadasz już tą odznakę, ale jej status to "wymaga zmian".'

                                status_response = 223
                                was_activated = True
                                set_main_badge = False


                            if not user.is_admin and only_title:  # JAK NIE ADMIN I TYLKO TYTUL - TO ZWROC SAM TYTUL, STATUS I ID ODZNAKI
                                badge = {"id": badge_code.badge.id,
                                         "verificated": badge_code.badge.verificated,
                                         "title_event": badge_code.badge.event.title}
                            else:
                                badge = BadgeActivateSerializer(
                                    badge_code.badge, context={'user': user}).data

                            return Response(
                                {'success': success_response, 'data': badge, "was_activated": was_activated, "set_main_badge": set_main_badge,
                                    "code": "7667"},
                                status=status_response
                            )

                        else:  # KOD ZOSTAŁ UŻYTY

                            return Response(
                                {'detail': 'Ten kod został już użyty.',
                                    "code": "1551"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                    else:
                        return Response(
                            {'detail': 'Nie można aktywować kodu, będąc jego stwórcą.',
                             "code": "1553"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                else:
                    return Response(
                        {'detail': 'Twój kod aktywacyjny jest błędny.',
                         "code": "1550"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych',
                    "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BadgeReportView(APIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = BadgeReportSerializer

    def post(self, request):
        try:
            response_verify = token_verify(request)
            if response_verify is not None:
                return response_verify
            else:
                data = request.data
                id_badge = data['id_badge']
                type = data['type']
                details = data.get('details', None)

                if str(id_badge).isdigit() and Badge.objects.filter(id=id_badge).exists():
                    user = request.user
                    badge = Badge.objects.get(id=id_badge)
                    if not badge.creator == user:

                        if badge.verificated == "verificated":

                            if not BadgeReport.objects.filter(badge=badge, user=user).exists():
                                BadgeReport.objects.create(
                                    badge=badge, user=user, type=type, details=details)

                                return Response(
                                    {'success': 'Sukces', "code": "1010"},
                                    status=status.HTTP_200_OK
                                )
                            else:
                                return Response(
                                    {'detail': 'Już wcześniej zgłosiłeś tą odznakę',
                                        "code": "9011"},
                                    status=status.HTTP_400_BAD_REQUEST
                                )

                        else:

                            if user.is_admin:

                                return Response(
                                    {'detail': 'Można zgłaszać tylko te odznaki, które są w danej chwili zweryfikowane.', "is_admin": user.is_admin, "status": {"status": badge.verificated, "details": badge.verificated_details},
                                        "code": "9011"},
                                    status=223
                                )
                            else:
                                return Response(
                                    {'detail': 'Można zgłaszać tylko te odznaki, które są w danej chwili zweryfikowane.', "is_admin": user.is_admin,
                                        "code": "9011"},
                                    status=223
                                )

                    else:
                        return Response(
                            {'detail': 'Nie możesz zgłosić odznaki, którą sam utworzyłeś',
                                "code": "9011"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {'detail': 'Nie ma takiej odznaki', "code": "9011"},
                        status=224
                    )

        except Exception as e:
            print(e)
            print(f"Typ błędu: {type(e).__name__}")
            print(f"Kod błędu: {e.args[0]}")
            print("Traceback:")
            import traceback
            traceback.print_tb(e.__traceback__)

            return Response(
                {'detail': 'Coś poszło nie tak z próbą pobrania danych', "code": "1165"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
