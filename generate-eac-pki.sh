#! /bin/sh

CURVES="prime192v1 brainpoolP192r1 secp224r1 brainpoolP224r1 prime256v1 brainpoolP256r1 brainpoolP512r1 secp384r1 brainpoolP384r1 brainpoolP512r1 secp521r1"
SCHEMES="ECDSA_SHA_1 ECDSA_SHA_1 ECDSA_SHA_224 ECDSA_SHA_256 ECDSA_SHA_384 ECDSA_SHA_512"

curve2dp() {
    local dp=""
    case $1 in
        prime192v1      ) dp="8";;
        brainpoolp192r1 ) dp="9";;
        secp224r1       ) dp="10";;
        brainpoolP224r1 ) dp="11";;
        prime256v1      ) dp="12";;
        brainpoolP256r1 ) dp="13";;
        brainpoolP512r1 ) dp="14";;
        secp384r1       ) dp="15";;
        brainpoolP384r1 ) dp="16";;
        brainpoolP512r1 ) dp="17";;
        secp521r1       ) dp="18";;
        *               ) echo not a valid curve: $1; exit 1;;
    esac
    return $dp
}

create_private_key() {
    REFERENCE=$1
    CURVE=$2

    openssl ecparam -out $REFERENCE.pem -name $CURVE -genkey
    openssl pkcs8 -topk8 -nocrypt -in $REFERENCE.pem -outform DER -out $REFERENCE.pkcs8
    rm -f $REFERENCE.pem
    echo "Created $REFERENCE.pkcs8"
}



# TODO implement overlapping validity periods

create_eac_pki() {
    TODAY="`date --date="today" "+%^y%^m%^d"`"
    ONEYEAR="`date --date="1 year" "+%^y%^m%^d"`"
    TWOYEAR="`date --date="2 year" "+%^y%^m%^d"`"
    SIXMONTH="`date --date="6 month" "+%^y%^m%^d"`"
    EIGHTTEENMONTH="`date --date="18 month" "+%^y%^m%^d"`"

    mkdir -p eac-pki_$TODAY
    cd eac-pki_$TODAY

    mkdir -p at && cd at

    PERMISSION_CALC="--rid --verify-community --verify-age"
    PERMISSION_RFU="--at-rfu32 --at-rfu31 --at-rfu30 --at-rfu29"
    PERMISSION_RW="$PERMISSION_CALC --write-dg17 --write-dg18 --write-dg19 --write-dg20 --write-dg21 --read-dg1 --read-dg2 --read-dg3 --read-dg4 --read-dg5 --read-dg6 --read-dg7 --read-dg8 --read-dg9 --read-dg10 --read-dg11 --read-dg12 --read-dg13 --read-dg14 --read-dg15 --read-dg16 --read-dg17 --read-dg18 --read-dg19 --read-dg20 --read-dg21"
    PERMISSION_ZDA=" --install-qual-cert --install-cert"
    PERMISSION_MOST="$PERMISSION_ZDA $PERMISSION_RW"
    PERMISSION_ALL="$PERMISSION_MOST $PERMISSION_RFU"

    for SCHEME in $SCHEMES
    do
        mkdir -p $SCHEME && cd $SCHEME

        for CURVE in $CURVES
        do
            mkdir -p $CURVE && cd $CURVE

            CVCA_REF=ZZATCVCA$TODAY
            create_private_key $CVCA_REF $CURVE
            cvc-create --out-cert=$CVCA_REF.cvcert \
                --role=cvca --type=at --chr=$CVCA_REF \
                --issued=$TODAY --expires=$ONEYEAR \
                --sign-with=$CVCA_REF.pkcs8 --scheme=$SCHEME \
                $PERMISSION_ALL
            LINK_REF=ZZATCVCA$ONEYEAR
            cvc-create --out-cert=$LINK_REF.cvcert \
                --role=cvca --sign-as=$CVCA_REF.cvcert --chr=$LINK_REF \
                --issued=$ONEYEAR --expires=$TWOYEAR \
                --sign-with=$CVCA_REF.pkcs8 --scheme=$SCHEME \
                $PERMISSION_ALL

            # generate a new key each time
            DVCA_REF=ZZATDVCA$TODAY
            cvc-create --out-cert=$DVCA_REF.cvcert \
                --role=dv_domestic --sign-as=$CVCA_REF.cvcert --chr=$DVCA_REF \
                --issued=$TODAY --expires=$SIXMONTH \
                --sign-with=$CVCA_REF.pkcs8 --scheme=$SCHEME \
                $PERMISSION_MOST
            DVCA_REF=ZZATDVCA$SIXMONTH
            cvc-create --out-cert=$DVCA_REF.cvcert \
                --role=dv_domestic --sign-as=$CVCA_REF.cvcert --chr=$DVCA_REF \
                --issued=$SIXMONTH --expires=$ONEYEAR \
                --sign-with=$CVCA_REF.pkcs8 --scheme=$SCHEME \
                $PERMISSION_MOST
            DVCA_REF=ZZATDVCA$ONEYEAR
            cvc-create --out-cert=$DVCA_REF.cvcert \
                --role=dv_domestic --sign-as=$CVCA_REF.cvcert --chr=$DVCA_REF \
                --issued=$ONEYEAR --expires=$EIGHTTEENMONTH \
                --sign-with=$CVCA_REF.pkcs8 --scheme=$SCHEME \
                $PERMISSION_MOST
            DVCA_REF=ZZATDVCA$EIGHTTEENMONTH
            cvc-create --out-cert=$DVCA_REF.cvcert \
                --role=dv_domestic --sign-as=$CVCA_REF.cvcert --chr=$DVCA_REF \
                --issued=$EIGHTTEENMONTH --expires=$TWOYEAR \
                --sign-with=$CVCA_REF.pkcs8 --scheme=$SCHEME \
                $PERMISSION_MOST

            i=1
            for PERMISSIONS in "$PERMISSION_MOST" "$PERMISSION_RW" "$PERMISSION_CALC"
            do
                TERMINAL_REF=ZZATTERM$i
                # reuse this key for every certificate
                create_private_key $TERMINAL_REF $CURVE
                DVCA_REF=ZZATDVCA$TODAY
                cvc-create --out-cert=$TERMINAL_REF""_$TODAY.cvcert \
                    --role=terminal --sign-as=$DVCA_REF.cvcert --chr=$TERMINAL_REF \
                    --issued=$TODAY --expires=$SIXMONTH \
                    --sign-with=$DVCA_REF.pkcs8 --scheme=$SCHEME \
                    --key=$TERMINAL_REF.pkcs8 $PERMISSIONS
                DVCA_REF=ZZATDVCA$SIXMONTH
                cvc-create --out-cert=$TERMINAL_REF""_$SIXMONTH.cvcert \
                    --role=terminal --sign-as=$DVCA_REF.cvcert --chr=$TERMINAL_REF \
                    --issued=$SIXMONTH --expires=$ONEYEAR \
                    --sign-with=$DVCA_REF.pkcs8 --scheme=$SCHEME \
                    --key=$TERMINAL_REF.pkcs8 $PERMISSIONS
                DVCA_REF=ZZATDVCA$ONEYEAR
                cvc-create --out-cert=$TERMINAL_REF""_$ONEYEAR.cvcert \
                    --role=terminal --sign-as=$DVCA_REF.cvcert --chr=$TERMINAL_REF \
                    --issued=$ONEYEAR --expires=$EIGHTTEENMONTH \
                    --sign-with=$DVCA_REF.pkcs8 --scheme=$SCHEME \
                    --key=$TERMINAL_REF.pkcs8 $PERMISSIONS
                DVCA_REF=ZZATDVCA$EIGHTTEENMONTH
                cvc-create --out-cert=$TERMINAL_REF""_$EIGHTTEENMONTH.cvcert \
                    --role=terminal --sign-as=$DVCA_REF.cvcert --chr=$TERMINAL_REF \
                    --issued=$EIGHTTEENMONTH --expires=$TWOYEAR \
                    --sign-with=$DVCA_REF.pkcs8 --scheme=$SCHEME \
                    --key=$TERMINAL_REF.pkcs8 $PERMISSIONS
                ((i++))
            done

            cd ..

        done

        cd ..
    done

    cd ..
    mkdir -p st && cd st

    PERMISSION_RFU="--st-rfu5 --st-rfu4 --st-rfu3 --st-rfu2"
    PERMISSION_MOST="--gen-qualified-sig --gen-sig"
    PERMISSION_ALL="$PERMISSION_MOST $PERMISSION_RFU"

    for SCHEME in $SCHEMES
    do
        mkdir -p $SCHEME && cd $SCHEME

        for CURVE in $CURVES
        do
            mkdir -p $CURVE && cd $CURVE

            CVCA_REF=ZZSTCVCA$TODAY
            create_private_key $CVCA_REF $CURVE
            cvc-create --out-cert=$CVCA_REF.cvcert \
                --role=cvca --type=at --chr=$CVCA_REF \
                --issued=$TODAY --expires=$TWOYEAR \
                --sign-with=$CVCA_REF.pkcs8 --scheme=$SCHEME \
                $PERMISSION_ALL

            # generate a new key each time
            DVCA_REF=ZZSTDVCA$TODAY
            cvc-create --out-cert=$DVCA_REF.cvcert \
                --role=dv_domestic --sign-as=$CVCA_REF.cvcert --chr=$DVCA_REF \
                --issued=$TODAY --expires=$TWOYEAR \
                --sign-with=$CVCA_REF.pkcs8 --scheme=$SCHEME \
                $PERMISSION_MOST

            TERMINAL_REF=ZZSTTERM$TODAY
            cvc-create --out-cert=$TERMINAL_REF.cvcert \
                --role=terminal --sign-as=$DVCA_REF.cvcert --chr=$TERMINAL_REF \
                --issued=$TODAY --expires=$TWOYEAR \
                --sign-with=$DVCA_REF.pkcs8 --scheme=$SCHEME \
                $PERMISSION_MOST

            cd ..
        done

        cd ..
    done
}

create_eac_pki
