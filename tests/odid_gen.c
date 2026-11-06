// Part of readsbee. GPL-3.0-or-later, see COPYING.
// Writes tests/vectors/odid_vectors.json: ODID messages encoded AND decoded by the reference
// Open Drone ID core library (opendroneid-core-c, Apache-2.0), so readsbee's decoder is checked
// against it. Not part of the build:
//   cc -I<odid>/libopendroneid -DODID_DISABLE_PRINTF tests/odid_gen.c <odid>/libopendroneid/opendroneid.c -lm -o odid_gen
//   ./odid_gen > tests/vectors/odid_vectors.json
// <odid> = PantsForBirds/adsbee firmware/modules/opendroneid-core-c

#include <stdio.h>
#include <string.h>
#include "opendroneid.h"

static int first = 1;

static void hex(const uint8_t *b, int n) {
    for (int i = 0; i < n; i++)
        printf("%02x", b[i]);
}

static void jstr(const char *s) {
    putchar('"');
    for (; *s; s++) {
        if ((unsigned char) *s < 32 || *s == '"' || *s == '\\')
            printf("\\u%04x", (unsigned char) *s);
        else
            putchar(*s);
    }
    putchar('"');
}

// expected values as the reference decoder reports them
static void expect(const uint8_t *raw, int n, const char *name, const char *note) {
    ODID_UAS_Data u;
    odid_initUasData(&u);
    if (raw[0] >> 4 == 0xF)
        decodeMessagePack(&u, (const ODID_MessagePack_encoded *) raw);
    else
        decodeOpenDroneID(&u, raw);
    printf("%s{\"name\":\"%s\",\"note\":\"%s\",\"hex\":\"", first ? "[\n" : ",\n", name, note);
    first = 0;
    hex(raw, n);
    printf("\",\"expect\":{");
    const char *sep = "";
    for (int i = 0; i < ODID_BASIC_ID_MAX_MESSAGES; i++) {
        if (u.BasicIDValid[i]) {
            printf("%s\"basic_id%d\":{\"id\":", sep, i);
            jstr(u.BasicID[i].UASID);
            printf(",\"id_type\":%d,\"ua_type\":%d}", u.BasicID[i].IDType, u.BasicID[i].UAType);
            sep = ",";
        }
    }
    if (u.LocationValid) {
        ODID_Location_data *l = &u.Location;
        printf("%s\"location\":{\"status\":%d,\"track\":%.2f,\"gs\":%.2f,\"vrate\":%.2f,\"lat\":%.7f,\"lon\":%.7f,"
                "\"alt_baro\":%.1f,\"alt_geo\":%.1f,\"height\":%.1f,\"height_type\":%d}", sep,
                l->Status, l->Direction, l->SpeedHorizontal, l->SpeedVertical, l->Latitude, l->Longitude,
                l->AltitudeBaro, l->AltitudeGeo, l->Height, l->HeightType);
        sep = ",";
    }
    if (u.SelfIDValid) {
        printf("%s\"self_id\":{\"type\":%d,\"text\":", sep, u.SelfID.DescType);
        jstr(u.SelfID.Desc);
        printf("}");
        sep = ",";
    }
    if (u.SystemValid) {
        ODID_System_data *s = &u.System;
        printf("%s\"system\":{\"loc_type\":%d,\"class_type\":%d,\"lat\":%.7f,\"lon\":%.7f,\"alt_geo\":%.1f,"
                "\"eu_category\":%d,\"eu_class\":%d}", sep, s->OperatorLocationType, s->ClassificationType,
                s->OperatorLatitude, s->OperatorLongitude, s->OperatorAltitudeGeo, s->CategoryEU, s->ClassEU);
        sep = ",";
    }
    if (u.OperatorIDValid) {
        printf("%s\"operator_id\":{\"type\":%d,\"id\":", sep, u.OperatorID.OperatorIdType);
        jstr(u.OperatorID.OperatorId);
        printf("}");
    }
    printf("}}");
}

int main(void) {
    ODID_BasicID_data b, b2;
    odid_initBasicIDData(&b);
    b.IDType = ODID_IDTYPE_SERIAL_NUMBER;
    b.UAType = ODID_UATYPE_HELICOPTER_OR_MULTIROTOR;
    strcpy(b.UASID, "1581F5FKD229400ABCDE");
    ODID_BasicID_encoded be, be2;
    encodeBasicIDMessage(&be, &b);
    expect((uint8_t *) &be, 25, "basic_id_serial", "serial number, multirotor");

    odid_initBasicIDData(&b2);
    b2.IDType = ODID_IDTYPE_SPECIFIC_SESSION_ID;
    b2.UAType = ODID_UATYPE_AEROPLANE;
    strcpy(b2.UASID, "\x01" "SESSION-7F3A");
    encodeBasicIDMessage(&be2, &b2);
    expect((uint8_t *) &be2, 25, "basic_id_session", "session ID, aeroplane");

    ODID_Location_data l;
    odid_initLocationData(&l);
    l.Status = ODID_STATUS_AIRBORNE;
    l.Direction = 271;
    l.SpeedHorizontal = 12.25f;
    l.SpeedVertical = -2.5f;
    l.Latitude = 47.3977419;
    l.Longitude = 8.5455938;
    l.AltitudeBaro = 485.0f;
    l.AltitudeGeo = 488.5f;
    l.HeightType = ODID_HEIGHT_REF_OVER_GROUND;
    l.Height = 40.5f;
    l.HorizAccuracy = ODID_HOR_ACC_10_METER;
    l.VertAccuracy = ODID_VER_ACC_10_METER;
    l.SpeedAccuracy = ODID_SPEED_ACC_1_METERS_PER_SECOND;
    l.TimeStamp = 1234.5f;
    ODID_Location_encoded le;
    encodeLocationMessage(&le, &l);
    expect((uint8_t *) &le, 25, "location", "airborne, track 271 (EW bit), AGL height");

    ODID_Location_data l2 = l;
    l2.Status = ODID_STATUS_GROUND;
    l2.Direction = 90;
    l2.SpeedHorizontal = 80.0f; // speed multiplier 0.75
    l2.SpeedVertical = 10.0f;
    l2.Latitude = -33.8688;
    l2.Longitude = 151.2093;
    l2.HeightType = ODID_HEIGHT_REF_OVER_TAKEOFF;
    ODID_Location_encoded le2;
    encodeLocationMessage(&le2, &l2);
    expect((uint8_t *) &le2, 25, "location_fast", "speed multiplier set, southern hemisphere");

    ODID_Location_data l3;
    odid_initLocationData(&l3); // everything invalid / unknown
    ODID_Location_encoded le3;
    encodeLocationMessage(&le3, &l3);
    expect((uint8_t *) &le3, 25, "location_invalid", "all fields invalid");

    ODID_SelfID_data s;
    odid_initSelfIDData(&s);
    s.DescType = ODID_DESC_TYPE_TEXT;
    strcpy(s.Desc, "Bridge inspection");
    ODID_SelfID_encoded se;
    encodeSelfIDMessage(&se, &s);
    expect((uint8_t *) &se, 25, "self_id", "text");

    ODID_System_data y;
    odid_initSystemData(&y);
    y.OperatorLocationType = ODID_OPERATOR_LOCATION_TYPE_LIVE_GNSS;
    y.ClassificationType = ODID_CLASSIFICATION_TYPE_EU;
    y.OperatorLatitude = 47.3970001;
    y.OperatorLongitude = 8.5450002;
    y.AreaCount = 1;
    y.AreaRadius = 0;
    y.AreaCeiling = -1000;
    y.AreaFloor = -1000;
    y.CategoryEU = ODID_CATEGORY_EU_OPEN;
    y.ClassEU = ODID_CLASS_EU_CLASS_1;
    y.OperatorAltitudeGeo = 450.0f;
    y.Timestamp = 249000000;
    ODID_System_encoded ye;
    encodeSystemMessage(&ye, &y);
    expect((uint8_t *) &ye, 25, "system", "operator live GNSS, EU open C1");

    ODID_OperatorID_data o;
    odid_initOperatorIDData(&o);
    o.OperatorIdType = ODID_OPERATOR_ID;
    strcpy(o.OperatorId, "FIN87astrdge12k8");
    ODID_OperatorID_encoded oe;
    encodeOperatorIDMessage(&oe, &o);
    expect((uint8_t *) &oe, 25, "operator_id", "EU operator registration");

    ODID_MessagePack_data pd;
    odid_initMessagePackData(&pd);
    pd.MsgPackSize = 5;
    memcpy(&pd.Messages[0], &be, 25);
    memcpy(&pd.Messages[1], &le, 25);
    memcpy(&pd.Messages[2], &se, 25);
    memcpy(&pd.Messages[3], &ye, 25);
    memcpy(&pd.Messages[4], &oe, 25);
    ODID_MessagePack_encoded pe;
    encodeMessagePack(&pe, &pd);
    expect((uint8_t *) &pe, 3 + 25 * 5, "pack", "Basic ID, Location, Self-ID, System, Operator ID (Wi-Fi style)");
    printf("\n]\n");
    return 0;
}
