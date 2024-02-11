
from front.models import Province, City, Event, MyUser, Category, County, AdminLog, DeleteModel, Notification
from django.contrib.gis.geos import Point
from django.contrib.gis.measure import D
import csv
import ast
from django.utils import timezone
from bs4 import BeautifulSoup
import json
from PIL import Image
from django.core.files import File


def InitModels():
    importProvince()
    importCountys()
    importCities()
    createModelsNotification()
    importCategorys()
    # # importEvents()
    # # deleteEvents()
    # createAdminLog()
    # writeToCsvDataCountyID()
    # addToPowiatyGeojsonInfoProvinceIDAndName()
    print("================= KONIEC ========================")


def importProvince():

    print("------------- WOJEWÓDZTWA ------------------")

    for province in dataProvince:
        print(province)

        obj, created = Province.objects.get_or_create(
            id=dataProvince[province], name=province)


def importCountys():
    print("------------- POWIATY ------------------")
    with open('front/files/coords/coord_simc_merge_powiaty.csv', encoding="utf8") as file:
        reader = csv.reader(file)

        for row in reader:

            print(dataCounty[int(row[4])])

            obj, created = County.objects.get_or_create(id=row[4], name=dataCounty[int(row[4])], province=Province.objects.get(
                id=row[2]))

        obj, created = County.objects.get_or_create(id=80, name=dataCounty[80], province=Province.objects.get(
            id=20))


def importCities():
    print("------------- MIASTA ------------------")
    with open('front/files/coords/coord_simc_merge_powiaty.csv', encoding="utf8") as file:
        reader = csv.reader(file)

        for row in reader:
            print(row[1])
            geo_location_coordinaty = row[3].split(" ")
            geo_location_coordinaty[0] = geo_location_coordinaty[0].replace(
                "°", ", ").replace("'", ", ")[:-1].split(", ")
            geo_location_coordinaty[1] = geo_location_coordinaty[1].replace(
                "°", ", ").replace("'", ", ")[:-1].split(", ")

            latitude_strip_list = [int(data.lstrip('0') or 0)
                                   for data in geo_location_coordinaty[0]]
            longitude_strip_list = [int(data.lstrip('0') or 0)
                                    for data in geo_location_coordinaty[1]]

            latitude = latitude_strip_list[0] + \
                latitude_strip_list[1]/60 + latitude_strip_list[2]/3600
            longitude = longitude_strip_list[0] + \
                longitude_strip_list[1]/60 + longitude_strip_list[2]/3600

            latitude = round(latitude, 6)
            longitude = round(longitude, 6)

            obj, created = City.objects.get_or_create(id=row[0], name=row[1], county=County.objects.get(
                id=int(row[4])), geo_location=Point(longitude, latitude))




def createModelsNotification():



    print("------------- MODELE POWIADOMIEŃ ------------------")



    notification_types = {
        'MyUser': {
            0: 'zaakceptowanie wysłanego zaproszenia do znajomych.',
        },
        'IPAddress': {
            8: 'wykryto logowanie z nowego adresu IP.',
            9: 'jeden z twoich adresów IP został zbanowany.',
        },
        'Event': {
            1: 'zaakceptowanie wydarzenia.',
            2: 'wydarzenie do ponownej weryfikacji.',
            3: 'wydarzenie zostało usunięte.',
        },
        'CommentEvent': {
            7: 'komentarz został zablokowany.',
        },
        'Badge': {
            4: 'zaakceptowanie odznaki.',
            5: 'odznaka do ponownej weryfikacji.',
            6: 'odznaka została usunięta.',
            10: 'aktywowana odznaka została usunięta.',
            11: 'twoja główna odznaka została usunięta.'
        },
        'Ticket': {
            12: 'zaakceptowanie biletu.',
            13: 'bilet do ponownej weryfikacji.',
            14: 'bilet został usunięty.',
        },
        'Order':{
            15: 'pieniądze za zamówienia zostały zwrócone.',
        },
        'AwaitingsTicketsRefund':{
            16: 'podłącz swoje konto bankowe w celu odebrania pieniędzy.'
        },
        'GatewayPaycheck':{
            17: 'przelew został przesłany na konto.'

        }
    }


    deleted_models_types = {
        'MyUser': 0,
        'IPAddress': 1,
        'Event': 2,
        'CommentEvent': 3,
        'Badge': 4,
        'Ticket': 5,
        'Order': 6,
        'AwaitingsTicketsRefund': 7,
        'GatewayPaycheck': 8,
    }


    for model_type in notification_types:
        model, created = DeleteModel.objects.get_or_create(id=deleted_models_types[model_type], content_type=model_type)
        

        for notification_type in notification_types[model_type]:
            notification, created = Notification.objects.get_or_create(id=notification_type, text=notification_types[model_type][notification_type], content_type=model_type)
            






def importCategorys():


    print("------------- KATEGORIE ------------------")

    

    categorys = [
        ["Sport i rekreacja", "zawody sportowe, imprezy rekreacyjne, maratony, wycieczki", "sports.png"],
        ["Turystyka", "imprezy turystyczne, prezentacje regionów turystycznych", "touristic.png"],
        ["Nauka i technologia", "konferencje naukowe, wystawy technologiczne, hackathony", "science.png"],
        ["Religia i duchowość", "uroczystości religijne, spotkania duchowe", "religious.png"],
        ["Polityka", "spotkania polityczne, demonstracje, debaty, wydarzenia społeczne", "politics.png"],
        ["Muzyka i taniec", "wydarzenia artystyczne, wystawy, koncerty, festiwale", "music.png"],
        ["Film i telewizja", "festiwale filmowe, pokazy filmowe, nagrody filmowe", "movie.png"],
        ["Życie codzienne", "jarmarki, festyny, imprezy miejskie", "lifestyle.png"],
        ["Moda i uroda", "pokazy mody, targi kosmetyczne, imprezy dla branży beauty", "fashion.png"],
        ["Edukacja i szkolenia", "kursy, warsztaty, szkolenia, konferencje edukacyjne", "education.png"],
        ["Ekologia", "wydarzenia związane z ochroną środowiska, ekologiczne festiwale", "ecology.png"],
        ["Biznes i finanse", "targi biznesowe, spotkania networkingowe, sesje szkoleniowe", "buisness.png"],
        ["Książki i literatura", "spotkania autorskie, targi książki, wykłady", "book.png"],
        ]
     



    for category in categorys:
        print(category[0])

        if not Category.objects.filter(type=category[0], details=category[1]).exists():

            path = "front/files/categorys/" + category[2]
            with open(path, 'rb') as image_file:
                django_file = File(image_file)

                obj = Category.objects.create(type=category[0], details=category[1])
                obj.image.save(category[2], django_file)



                



# def deleteEvents():
#     Event.objects.all().delete()


# def createAdminLog():

#     for row in range(150):
#         print(row)

#         AdminLog.objects.create(user=MyUser.objects.get(
#             username="admin"), action_flag="deletion", content_type="IPAddress", id_content_type=1)


# def importEvents():
#     objects_list = City.objects.filter().order_by('?')

#     for row in range(400):
#         print(row)

#         Event.objects.create(user=MyUser.objects.get(username="admin"), category=Category.objects.get(
#             type="Sport i rekreacja"), title="Orange Warsaw Festival 2023", text=Event.objects.first().text, image=Event.objects.first().image, event_date=timezone.now(), city=objects_list[row])

dataProvince = {
    "Dolnośląskie": 2,
    "Kujawsko-Pomorskie": 4,
    "Lubelskie": 6,
    "Lubuskie": 8,
    "Łódzkie": 10,
    "Małopolskie": 12,
    "Mazowieckie": 14,
    "Opolskie": 16,
    "Podkarpackie": 18,
    "Podlaskie": 20,
    "Pomorskie": 22,
    "Śląskie": 24,
    "Świętokrzyskie": 26,
    "Warmińsko-Mazurskie": 28,
    "Wielkopolskie": 30,
    "Zachodniopomorskie": 32
}


dataCounty = {
    1: "powiat ropczycko-sędziszowski",
    2: "powiat łosicki",
    3: "powiat piaseczyński",
    4: "powiat radomski",
    5: "powiat sierpecki",
    6: "powiat szydłowiecki",
    7: "powiat węgrowski",
    8: "powiat gostyniński",
    9: "powiat grodziski",
    10: "powiat łukowski",
    11: "powiat tomaszowski",
    12: "powiat Chełm",
    13: "powiat brzeski",
    14: "powiat Kraków",
    15: "powiat zgierski",
    16: "powiat sulęciński",
    17: "powiat łańcucki",
    18: "powiat brzeski",
    19: "powiat ostrzeszowski",
    20: "powiat Radom",
    21: "powiat żyrardowski",
    22: "powiat obornicki",
    23: "powiat leszczyński",
    24: "powiat Siedlce",
    25: "powiat Leszno",
    26: "powiat kolski",
    27: "powiat Łomża",
    28: "powiat rawicki",
    29: "powiat słupecki",
    30: "powiat kościerski",
    31: "powiat włoszczowski",
    32: "powiat stargardzki",
    33: "powiat Wrocław",
    34: "powiat giżycki",
    35: "powiat mrągowski",
    36: "powiat głogowski",
    37: "powiat choszczeński",
    38: "powiat Sosnowiec",
    39: "powiat rybnicki",
    40: "powiat Gliwice",
    41: "powiat Piekary Śląskie",
    42: "powiat Jaworzno",
    43: "powiat inowrocławski",
    44: "powiat brodnicki",
    45: "powiat włocławski",
    46: "powiat mogileński",
    47: "powiat Toruń",
    48: "powiat tucholski",
    49: "powiat raciborski",
    50: "powiat cieszyński",
    51: "powiat krośnieński",
    52: "powiat nyski",
    53: "powiat Jelenia Góra",
    54: "powiat zgorzelecki",
    55: "powiat przasnyski",
    56: "powiat Ostrołęka",
    57: "powiat średzki",
    58: "powiat jarociński",
    59: "powiat Gdynia",
    60: "powiat Świnoujście",
    61: "powiat kamiennogórski",
    62: "powiat pabianicki",
    63: "powiat kolneński",
    64: "powiat Opole",
    65: "powiat ostródzki",
    66: "powiat przemyski",
    67: "powiat Przemyśl",
    68: "powiat warszawski zachodni",
    69: "powiat włodawski",
    70: "powiat Lublin",
    71: "powiat bocheński",
    72: "powiat Tarnów",
    73: "powiat wschowski",
    74: "powiat gorzowski",
    75: "powiat międzyrzecki",
    76: "powiat słubicki",
    77: "powiat nowotomyski",
    78: "powiat wągrowiecki",
    79: "powiat bielski",
    80: "powiat suwalski",
    81: "powiat słupski",
    82: "powiat ostrowiecki",
    83: "powiat skarżyski",
    84: "powiat kartuski",
    85: "powiat częstochowski",
    86: "powiat pyrzycki",
    87: "powiat Siemianowice Śląskie",
    88: "powiat Elbląg",
    89: "powiat gryfiński",
    90: "powiat Bytom",
    91: "powiat złotoryjski",
    92: "powiat wrocławski",
    93: "powiat milicki",
    94: "powiat lubiński",
    95: "powiat lipnowski",
    96: "powiat żniński",
    97: "powiat radziejowski",
    98: "powiat nakielski",
    99: "powiat bartoszycki",
    100: "powiat żywiecki",
    101: "powiat sokólski",
    102: "powiat jasielski",
    103: "powiat głubczycki",
    104: "powiat nowosądecki",
    105: "powiat Zielona Góra",
    106: "powiat Skierniewice",
    107: "powiat żagański",
    108: "powiat Gdańsk",
    109: "powiat lęborski",
    110: "powiat Łódź",
    111: "powiat piotrkowski",
    112: "powiat ostrowski",
    113: "powiat starogardzki",
    114: "powiat Poznań",
    115: "powiat Konin",
    116: "powiat stalowowolski",
    117: "powiat Tarnobrzeg",
    118: "powiat płoński",
    119: "powiat mławski",
    120: "powiat siedlecki",
    121: "powiat garwoliński",
    122: "powiat lipski",
    123: "powiat hrubieszowski",
    124: "powiat kraśnicki",
    125: "powiat łęczyński",
    126: "powiat opolski",
    127: "powiat rycki",
    128: "powiat Zamość",
    129: "powiat dąbrowski",
    130: "powiat krakowski",
    131: "powiat wieruszowski",
    132: "powiat żarski",
    133: "powiat krośnieński",
    134: "powiat dębicki",
    135: "powiat namysłowski",
    136: "powiat czarnkowsko-trzcianecki",
    137: "powiat Płock",
    138: "powiat grajewski",
    139: "powiat starachowicki",
    140: "powiat konecki",
    141: "powiat elbląski",
    142: "powiat nidzicki",
    143: "powiat nowomiejski",
    144: "powiat Ruda Śląska",
    145: "powiat białogardzki",
    146: "powiat tarnogórski",
    147: "powiat zawierciański",
    148: "powiat Chorzów",
    149: "powiat Katowice",
    150: "powiat bolesławiecki",
    151: "powiat Wałbrzych",
    152: "powiat sępoleński",
    153: "powiat Włocławek",
    154: "powiat hajnowski",
    155: "powiat chrzanowski",
    156: "powiat wejherowski",
    157: "powiat Szczecin",
    158: "powiat pucki",
    159: "powiat rawski",
    160: "powiat łowicki",
    161: "powiat skierniewicki",
    162: "powiat iławski",
    163: "powiat niżański",
    164: "powiat tarnobrzeski",
    165: "powiat nowodworski",
    166: "powiat pruszkowski",
    167: "powiat przysuski",
    168: "powiat białobrzeski",
    169: "powiat wyszkowski",
    170: "powiat biłgorajski",
    171: "powiat chełmski",
    172: "powiat parczewski",
    173: "powiat świdnicki",
    174: "powiat kutnowski",
    175: "powiat łódzki wschodni",
    176: "powiat kolbuszowski",
    177: "powiat oleski",
    178: "powiat strzelecki",
    179: "powiat złotowski",
    180: "powiat Suwałki",
    181: "powiat kościański",
    182: "powiat grodziski",
    183: "powiat szamotulski",
    184: "powiat Kielce",
    185: "powiat staszowski",
    186: "powiat ełcki",
    187: "powiat dzierżoniowski",
    188: "powiat tczewski",
    189: "powiat kołobrzeski",
    190: "powiat Koszalin",
    191: "powiat kłobucki",
    192: "powiat gliwicki",
    193: "powiat lubliniecki",
    194: "powiat Bielsko-Biała",
    195: "powiat Legnica",
    196: "powiat grudziądzki",
    197: "powiat wołowski",
    198: "powiat toruński",
    199: "powiat chełmiński",
    200: "powiat wodzisławski",
    201: "powiat leski",
    202: "powiat bieszczadzki",
    203: "powiat prudnicki",
    204: "powiat ząbkowicki",
    205: "powiat makowski",
    206: "powiat pszczyński",
    207: "powiat gołdapski",
    208: "powiat Sopot",
    209: "powiat rzeszowski",
    210: "powiat jeleniogórski",
    211: "powiat świdnicki",
    212: "powiat opoczyński",
    213: "powiat człuchowski",
    214: "powiat ostrowski",
    215: "powiat Kalisz",
    216: "powiat strzyżowski",
    217: "powiat miński",
    218: "powiat zwoleński",
    219: "powiat żuromiński",
    220: "powiat lubelski",
    221: "powiat proszowicki",
    222: "powiat wielicki",
    223: "powiat sieradzki",
    224: "powiat brzeziński",
    225: "powiat strzelecko-drezdenecki",
    226: "powiat świebodziński",
    227: "powiat leżajski",
    228: "powiat lubaczowski",
    229: "powiat chodzieski",
    230: "powiat międzychodzki",
    231: "powiat kluczborski",
    232: "powiat jędrzejowski",
    233: "powiat gostyński",
    234: "powiat kazimierski",
    235: "powiat kaliski",
    236: "powiat siemiatycki",
    237: "powiat gdański",
    238: "powiat szczycieński",
    239: "powiat łobeski",
    240: "powiat gryficki",
    241: "powiat myszkowski",
    242: "powiat oleśnicki",
    243: "powiat strzeliński",
    244: "powiat wąbrzeski",
    245: "powiat kętrzyński",
    246: "powiat białostocki",
    247: "powiat augustowski",
    248: "powiat wałbrzyski",
    249: "powiat kłodzki",
    250: "powiat Tychy",
    251: "powiat Rybnik",
    252: "powiat sokołowski",
    253: "powiat grójecki",
    254: "powiat lubartowski",
    255: "powiat puławski",
    256: "powiat radzyński",
    257: "powiat Biała Podlaska",
    258: "powiat Nowy Sącz",
    259: "powiat Gorzów Wielkopolski",
    260: "powiat pilski",
    261: "powiat wysokomazowiecki",
    262: "powiat buski",
    263: "powiat śremski",
    264: "powiat kępiński",
    265: "powiat turecki",
    266: "powiat opatowski",
    267: "powiat Słupsk",
    268: "powiat pińczowski",
    269: "powiat koszaliński",
    270: "powiat bielski",
    271: "powiat będziński",
    272: "powiat węgorzewski",
    273: "powiat bieruńsko-lędziński",
    274: "powiat policki",
    275: "powiat polkowicki",
    276: "powiat Jastrzębie-Zdrój",
    277: "powiat tatrzański",
    278: "powiat nowotarski",
    279: "powiat lwówecki",
    280: "powiat legionowski",
    281: "powiat olecki",
    282: "powiat tomaszowski",
    283: "powiat zambrowski",
    284: "powiat bytowski",
    285: "powiat płocki",
    286: "powiat pułtuski",
    287: "powiat sochaczewski",
    288: "powiat ciechanowski",
    289: "powiat bialski",
    290: "powiat krasnostawski",
    291: "powiat zamojski",
    292: "powiat tarnowski",
    293: "powiat bełchatowski",
    294: "powiat łaski",
    295: "powiat łęczycki",
    296: "powiat pajęczański",
    297: "powiat radomszczański",
    298: "powiat zduńskowolski",
    299: "powiat nowosolski",
    300: "powiat jarosławski",
    301: "powiat mielecki",
    302: "powiat Warszawa",
    303: "powiat krapkowicki",
    304: "powiat moniecki",
    305: "powiat kielecki",
    306: "powiat wrzesiński",
    307: "powiat gnieźnieński",
    308: "powiat malborski",
    309: "powiat lidzbarski",
    310: "powiat olsztyński",
    311: "powiat sławieński",
    312: "powiat działdowski",
    313: "powiat górowski",
    314: "powiat sztumski",
    315: "powiat kwidzyński",
    316: "powiat Dąbrowa Górnicza",
    317: "powiat Mysłowice",
    318: "powiat myśliborski",
    319: "powiat golubsko-dobrzyński",
    320: "powiat aleksandrowski",
    321: "powiat świecki",
    322: "powiat pleszewski",
    323: "powiat Krosno",
    324: "powiat sejneński",
    325: "powiat sanocki",
    326: "powiat suski",
    327: "powiat zielonogórski",
    328: "powiat wołomiński",
    329: "powiat mikołowski",
    330: "powiat goleniowski",
    331: "powiat Rzeszów",
    332: "powiat łomżyński",
    333: "powiat opolski",
    334: "powiat wałecki",
    335: "powiat drawski",
    336: "powiat chojnicki",
    337: "powiat przeworski",
    338: "powiat otwocki",
    339: "powiat kozienicki",
    340: "powiat janowski",
    341: "powiat limanowski",
    342: "powiat miechowski",
    343: "powiat myślenicki",
    344: "powiat olkuski",
    345: "powiat oświęcimski",
    346: "powiat Piotrków Trybunalski",
    347: "powiat poddębicki",
    348: "powiat wieluński",
    349: "powiat brzozowski",
    350: "powiat kędzierzyńsko-kozielski",
    351: "powiat krotoszyński",
    352: "powiat Białystok",
    353: "powiat wolsztyński",
    354: "powiat sandomierski",
    355: "powiat szczecinecki",
    356: "powiat świdwiński",
    357: "powiat piski",
    358: "powiat Świętochłowice",
    359: "powiat Zabrze",
    360: "powiat Olsztyn",
    361: "powiat braniewski",
    362: "powiat kamieński",
    363: "powiat Częstochowa",
    364: "powiat trzebnicki",
    365: "powiat bydgoski",
    366: "powiat oławski",
    367: "powiat średzki",
    368: "powiat legnicki",
    369: "powiat Bydgoszcz",
    370: "powiat Grudziądz",
    371: "powiat rypiński",
    372: "powiat gorlicki",
    373: "powiat lubański",
    374: "powiat wadowicki",
    375: "powiat ostrołęcki",
    376: "powiat Żory",
    377: "powiat nowodworski",
    378: "powiat jaworski",
    379: "powiat poznański",
    380: "powiat koniński"
}


# def writeToCsvDataCountyID():
#     with open('front/files/coords/miasta.html', 'r', encoding='utf8') as f:
#         contents = f.read()

#     soup = BeautifulSoup(contents, 'html.parser')

#     city_to_district = {}

#     for tr in soup.find_all('tr'):
#         city_name = tr.find_all('td')[1].get_text(strip=True)
#         district_name = tr.find_all('td')[2].get_text(strip=True)
#         city_to_district[city_name] = district_name

#     with open('front/files/coords/zobaczemym.csv', 'r', encoding="utf8") as f_in, open('front/files/coords/output.csv', 'w', newline='', encoding="utf8") as f_out:
#         reader = csv.reader(f_in)
#         writer = csv.writer(f_out)
#         for row in reader:
#             city_name = row[1]
#             # jeśli nie ma powiatu, zwróć 'N/A'
#             district_name = city_to_district.get(city_name, 'N/A')

#             for key, value in dataCounty.items():
#                 if value == district_name:
#                     break  # zakończ pętlę po znalezieniu pierwszego klucza
#             # # ZAZNACZONE ZEBY NIE ZAPISYWAC
#             # row.append(key)  # dodaj id powiatu jako piątą wartość
#             # writer.writerow(row)
#             # # ZAZNACZONE ZEBY NIE ZAPISYWAC


# def addToPowiatyGeojsonInfoProvinceIDAndName():

#     with open('front/files/coords/powiaty_test.geojson', 'r', encoding="utf8") as f:
#         data = json.load(f)

#     for feature in data['features']:
#         # Zastąp 'id' kluczem używanym w pliku GeoJSON
#         county_id = feature['properties']['id']
#         county = County.objects.get(id=county_id)
#         print(county.id)
#         print(county.name)
#         print(county.province.id)
#         print(county.province.name)
#         print("==================================")
#         feature['properties']['province_id'] = int(county.province.id)
#         feature['properties']['province_nazwa'] = county.province.name

#     # Zapisz zaktualizowany plik GeoJSON
#     with open('front/files/coords/powiaty_test_new.geojson', 'w', encoding="utf8") as f:
#         json.dump(data, f, ensure_ascii=False)
