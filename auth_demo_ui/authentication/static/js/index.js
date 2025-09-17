$(function() {
    const ids = {
        "firstName": "firstName",
        "lastName": "lastName",
        "middleName": "middleName",
        "name": "name",
        "gender": "gender",
        "emailId": "emailId",
        "phoneNumber": "phoneNumber",

        "age": "age",
        "bloodType": "bloodType",
        "maritalStatus": "maritalStatus",
        "dob": "dob",
        "postalCode": "postalCode",
        "pobProvince": "pobProvince",
        "pobCity": "pobCity",

        "residenceStatus": "residenceStatus",
        "presentCity": "presentCity",
        "presentBarangay": "presentBarangay",
        "presentProvince": "presentProvince",
        "presentAddress": "presentAddress",
        "presentAddressLine1": "presentAddressLine1",
        "fullAddress": "fullAddress",

        "permanentProvince": "permanentProvince",
        "permanentAddress": "permanentAddress",
        "permanentFullAddress": "permanentFullAddress",
        "permanentCity": "permanentCity",
        "permanentZipcode": "permanentZipcode",
        "permanentBarangay": "permanentBarangay",
        "permanentAddressLine1": "permanentAddressLine1",
    };

    
    const demog_id_value = {
        "firstName": false,
        "lastName": false,
        "middleName": false,
        "name": false,
        "gender": false,
        "emailId": false,
        "phoneNumber": false,

        "age": false,
        "bloodType": false,
        "maritalStatus": false,
        "dob": false,
        "postalCode": false,
        "pobProvince": false,
        "pobCity": false,

        "residenceStatus": false,
        "presentCity": false,
        "presentBarangay": false,
        "presentProvince": false,
        "presentAddress": false,
        "presentAddressLine1": false,
        "fullAddress": false,

        "permanentProvince": false,
        "permanentAddress": false,
        "permanentFullAddress": false,
        "permanentCity": false,
        "permanentZipcode": false,
        "permanentBarangay": false,
        "permanentAddressLine1": false,
    };
    
    const id_label = {
        "firstName": "First Name",
        "lastName": "Last name",
        "middleName": "Middle Name",
        "name": "Full Name",
        "gender": "Gender",
        "emailId": "Email Address",
        "phoneNumber": "Mobile Number",

        "age": "Age",
        "bloodType": "bloodType",
        "maritalStatus": "Martial Status",
        "dob": "Date of Birth",
        "postalCode": "Postal Code",
        "pobProvince": "Place of Birth (Province)",
        "pobCity": "Place of Birth (City)",

        "residenceStatus": "Residence Status",
        "presentCity": "Present Address (City)",
        "presentBarangay": "Present Address (Barangay)",
        "presentProvince": "Present Address (Province)",
        "presentAddress": "Present Address (House Number)",
        "presentAddressLine1": "Present Address (House Number din ata?)",
        "fullAddress": "Present Address (Full Address)",

        "permanentProvince": "Permanent Address (Province)",
        "permanentAddress": "Permament Address (Home Number)",
        "permanentFullAddress": "Permament Address (Full Address)",
        "permanentCity": "Permanent Address (City)",
        "permanentZipcode": "Permanent Address (Zip Code)",
        "permanentBarangay": "Permanent Address (Barangay)",
        "permanentAddressLine1": "Permament Address (Home Number din ata?)",
    };
    
    const category_contents = {
        1: [
            "firstName",
            "lastName",
            "middleName",
            "name",
            "gender",
            "emailId",
            "phoneNumber",
        ],

        2: [
            "age",
            "bloodType",
            "maritalStatus",
            "dob",
            "postalCode",
            "pobProvince",
            "pobCity",
        ],

        3: [
            "residenceStatus",
            "presentCity",
            "presentBarangay",
            "presentProvince",
            "presentAddress",
            "presentAddressLine1",
            "fullAddress",
        ],

        4: [
            "permanentProvince",
            "permanentAddress",
            "permanentFullAddress",
            "permanentCity",
            "permanentZipcode",
            "permanentBarangay",
            "permanentAddressLine1",
        ],
    };

    disableFingerPrintForm(true);
    disableIrisForm(true);
    disableFaceForm(true);
    disableOTPForm(true);
    disableDemographicForm(true);
    hideDemographicInputCategory();

    $("#category_page1").click(function() {
        hideDemographicInputCategory();
        $("#modal-demog-default").hide();
        $("#modal-demog-input-category-1").show();
        setActiveCategory('category_page1');
    });

    $("#category_page2").click(function() {
        hideDemographicInputCategory();
        $("#modal-demog-default").hide();
        $("#modal-demog-input-category-2").show();
        setActiveCategory('category_page2');
    });

    $("#category_page3").click(function() {
        hideDemographicInputCategory();
        $("#modal-demog-default").hide();
        $("#modal-demog-input-category-3").show();
        setActiveCategory('category_page3');
    });

    $("#category_page4").click(function() {
        hideDemographicInputCategory();
        $("#modal-demog-default").hide();
        $("#modal-demog-input-category-4").show();
        setActiveCategory('category_page4');
    });

    $("#model-demog-input-save").click(function() {
        var demog_result_id = 1;

        $("div[id^=demog-result-]").html("");

        $.each(id_label, function(key, value) {
            if($("#chkbox_demog_" + key).is(':checked')) {
                // $("#demog_value_" + value).show();
                var result = "";
                
                result += "<div class=\"form-group\">";
                result += "    <label for=\"" + key + "\">" + value + "</label>";
                result += "    <input type=\"" + (key == "dob" ? "date": "text") + "\" class=\"form-control\" id=\"demog_" + key + "\" placeholder=\"Enter " + value + "\">";
                result += "</div>";
                $("#demog-result-" + (demog_result_id % 4 == 0 ? "4" : demog_result_id % 4)).append(result);
                demog_result_id += 1;
            }
            else {
                $("#demog_" + key).hide();
            }
        });

        $("#model-demog-inputs").modal('toggle');
    });

    function setActiveCategory(selectedCategoryId) {
        var categories = document.querySelectorAll('.list-group-item');
        categories.forEach(function (category) {
            category.classList.remove('active');
        });
        document.getElementById(selectedCategoryId).classList.add('active');
    }

    // Token Value

    $("#auth-type-fp").change(function() {
        disableFingerPrintForm(!$(this).prop("checked"));
    });

    $("#auth-type-iris").change(function() {
        disableIrisForm(!$(this).prop("checked"));
    });

    $("#auth-type-face").change(function() {
        disableFaceForm(!$(this).prop("checked"));
    });

    $("#auth-type-otp").change(function() {
        disableOTPForm(!$(this).prop("checked"));
    });

    $("#auth-type-demo").change(function() {
        disableDemographicForm(!$(this).prop("checked"));
    });

    $("#btn-model-demog-inputs").click(function() {
        $("#model-demog-inputs").modal('toggle');
    });

    $("#otp-request").click(function() {
        var individual_id = $("#individual-id").val();
        var individual_id_type = $("#individual-id-type").val();
        var otp_email = $("#otp-email").prop("checked");
        var otp_phone = $("#otp-phone").prop("checked");
        var otp_channel = [];
        var csrf_token = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

        $("#loading_screen_message").html("Requesting OTP...")
        $("#loading_screen").show();

        if (otp_email) {
            otp_channel.push("Email");
        }
        
        if (otp_phone) {
            otp_channel.push("Phone");
        }

        $.ajax({
            type:"POST",
            headers: {
                "content-type": "application/json",
                "accept": "*/*",
                'X-CSRFToken': csrf_token,
            },
            url:"/request/otp/",
            // url:"http://localhost/request/otp/" + individual_id,
            data: JSON.stringify({
                // _token: _token,
                individual_id: individual_id,
                individual_id_type: individual_id_type,
                otp_channel: otp_channel,
            }),
            success:function(data) {
                $("#loading_screen").hide();
                resetAuthenticationResult();
                var result = JSON.stringify(data, null, 4);
                $("#modal-result-header").html("Request OTP result");
                $("#modal-result-value").text(result);
                $("#modal-result").modal("toggle");
            }
         });
    });

    var biometric_input = "";

    $("#biometric-capture").click(function() {
        biometric_input = [];
        if($("#auth-type-fp").is(':checked')) {
            deviceDiscovery("Finger", $("#fingers-count").val());
        }
        
        if($("#auth-type-iris").is(':checked')){
            deviceDiscovery("Iris",  $("#iris-type").val());
        }

        if($("#auth-type-face").is(':checked')) {
            deviceDiscovery("Face", 1);
        }
    });

    const deviceDiscovery = async (type, fingers_count, port_start = 4501, port_end = 4506, found = false) => {
        $("#loading_screen_message").html(`Checking port ${port_start}...`);
        $("#loading_screen").show();
        try {
            const response = await fetch("http://127.0.0.1:" + port_start + "/device", {
                method: "MOSIPDISC",
                headers: {
                    "content-type": "application/json",
                    "accept": "*/*",
                },
                body: JSON.stringify({
                    type: type
                })
            });
    
            const data = await response.text();
    
            if(data && data !== "undefined") {
                const parsed = JSON.parse(data)[0];
    
                const serial = parsed.deviceId;
                const errorCode = parsed.error ?. errorCode;
                const deviceStatus = parsed.deviceStatus;
                const version = parsed.serviceVersion;
    
                if(errorCode == 0 && deviceStatus === "Ready" && serial && serial !== "undefined") {
                    found = true;
                    biometricCapture(type, fingers_count, port_start, version, serial);
                }
    
            }
        }
        catch(e) {
            // console.log(`Error 4: ${e}`);
        }

        if(port_start < port_end && !found) {
            deviceDiscovery(type, fingers_count, port_start + 1);
        }
        else if(!found) {
            $("#loading_screen").hide();
            var result = JSON.stringify({
                error_code: "RP-AUTH-001",
                error_message: "Unable to fetch active biometric."
            }, null, 4);
            $("#modal-result-header").html("Biometric Error");
            $("#modal-result-value").text(result);
            $("#modal-result").modal("toggle");
        }
    }

    async function biometricCapture(type, count, port, version, deviceId) {
        const date = new Date().toISOString();
        $("#loading_screen_message").html(`Capturing biometrics at port ${port}...`);
        await fetch("http://127.0.0.1:" + port + "/capture", {
            method: "CAPTURE",
            headers: {
                "content-type": "application/json",
                "accept": "*/*",
            },
            body: JSON.stringify({
                "env": "Staging",
                "purpose": "Auth",
                // "specVersion": "0.9.5.1.5",
                "specVersion": version,
                "timeout": "300000",
                "captureTime": date,
                "domainUri": "https://api.apps-external.uat2.phylsys.gov.ph",
                "transactionId": "1234567890",
                "bio": [
                    {
                        "type": type,
                        "count": count,
                        "bioSubType": [
                            "UNKNOWN"
                        ],
                        "requestedScore": "60",
                        "deviceId": deviceId,
                        "deviceSubId": "1",
                        "previousHash": ""
                    }
                ],
                "customOpts": [
                    {
                        "name": "name1",
                        "value": "value1"
                    }
                ]
            })
        })
        .then(response => response.json())  // Parse the response as JSON
        .then(data => {                
            var data = data.biometrics;
            $("#loading_screen").hide();
            resetAuthenticationResult();
            var result = JSON.stringify(data, null, 4);
            
            $.merge(biometric_input, data);
            // biometric_input = data;

            $("#modal-result-header").html("Biometric");
            $("#modal-result-value").text(result);
            $("#modal-result").modal("toggle");
        })
        .catch(error => {
            console.log(error);
        });
    } 

    $("#send-auth-request").click(function() {
        var demog_value = {};
        var csrf_token = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

        if($("#auth-type-demo").is(':checked')) {
            $.each(ids, function(key, value) {
                if($("#demog_" + value).val() != "" && $("#demog_" + value).val() != null) {
                    demog_value[key] = $("#demog_" + value).val();
                    if(key == "dob") {
                        demog_value[key] = new Date(demog_value[key]);
                        demog_value[key] = demog_value[key].getFullYear() + '/' + ('0' + (demog_value[key].getMonth() + 1)).slice(-2) + '/' + ('0' + demog_value[key].getDate()).slice(-2);;
                    }
                }
            });
        }
        
        $("#loading_screen_message").html("Authenticating...")
        $("#loading_screen").show();

        fetch("/authenticate/", {
        // fetch("http://localhost/authenticate", {
            method: "POST",
            headers: {
                "content-type": "application/json",
                "accept": "*/*",
                "X-CSRFToken": csrf_token,
            },
            body: JSON.stringify({
                "individual_id": $("#individual-id").val(),
                "individual_id_type": $("#individual-id-type").val(),

                "is_ekyc": $("#auth-type-ekyc").is(':checked'),

                "otp_value": $("#auth-type-otp").is(':checked') ? $("#otp-value").val() : null,
                "demo_value":  $("#auth-type-demo").is(':checked') ? demog_value : null,
                "bio_value": ($("#auth-type-fp").is(':checked') || $("#auth-type-iris").is(':checked') || $("#auth-type-face").is(':checked')) ? biometric_input : null,
            })
        })
        .then(response => response.json())
        .then(data => {
            resetAuthenticationResult();
            $("#loading_screen").hide();
            if(data.kycStatus) {
                var identity = data.identity
                $("#ekyc_last_name").html(identity.lastName_eng ? identity.lastName_eng : "N/A");
                $("#ekyc_first_name").html(identity.firstName_eng ? identity.firstName_eng : "N/A");
                $("#ekyc_middle_name").html(identity.middleName_eng ? identity.middleName_eng : "N/A");
                $("#ekyc_suffix").html(identity.suffix_eng ? identity.suffix_eng : "N/A");
                $("#ekyc_dob").html(identity.dob ? identity.dob : "N/A");
                $("#ekyc_phone_number").html(identity.phoneNumber ? identity.phoneNumber : "N/A");
                $("#ekyc_email").html(identity.emailId ? identity.emailId : "N/A");
                $("#ekyc_age").html(identity.age ? identity.age : "N/A");
                $("#ekyc_marital_status").html(identity.maritalStatus_eng ? identity.maritalStatus_eng : "N/A");
                $("#ekyc_country").html(identity.pobCountry_eng ? identity.pobCountry_eng : "N/A");
                $("#ekyc_present_address").html(identity.presentAddress_eng ? identity.presentAddress_eng : "N/A");
                $("#ekyc_province").html(identity.location1_eng ? identity.location1_eng : "N/A");
                $("#ekyc_municipality").html(identity.location2_eng ? identity.location2_eng : "N/A");
                $("#ekyc_barangay").html(identity.location3_eng ? identity.location3_eng : "N/A");
                $("#ekyc_postal_code").html(identity.postalCode ? identity.postalCode : "N/A");
                $("#ekyc_blood_type").html(identity.bloodType_eng ? identity.bloodType_eng : "N/A");
                $("#ekyc_residence_status").html(identity.residenceStatus_eng ? identity.residenceStatus_eng : "N/A");
                $("#ekyc_photo").attr("src", "data:image/png;base64," + identity.photo);
                $("#ekyc_auth_token").html(data.authToken ? data.authToken : "N/A");

                $("#ekyc_result").show();
            }
            else {
                var result = JSON.stringify(data, null, 4);
                $("#modal-result-value").text(result);
            }

            $("#modal-result-header").html("Authentication Result");
            $("#modal-result").modal("toggle");
        })
        .catch(error => {
            console.log("Error: " + error);
        });
    });
});

function disableFingerPrintForm(value) {
    $("#fingers-count").attr("disabled", value);
    $("#biometric-capture").attr("disabled", value);
}

function disableIrisForm(value) {
    $("#iris-type").attr("disabled", value);
    $("#biometric-capture").attr("disabled", value);
}

function disableFaceForm(value) {
    $("#biometric-capture").attr("disabled", value);
}

function disableOTPForm(value) {
    $("#otp-request").attr("disabled", value);
    $("#otp-value").attr("disabled", value);
    $("#otp-email").attr("disabled", value);
    $("#otp-phone").attr("disabled", value);
}

function disableDemographicForm(value) {
    $("#demographic-value").attr("disabled", value);
    $("#btn-model-demog-inputs").attr("disabled", value);
    $("input[id^=demog_]").attr("disabled", value);
}

function hideDemographicInputCategory() {
    $("div[id^=modal-demog-input-category-]").hide();
}

function resetAuthenticationResult() {
    $("#ekyc_result").hide();
    $("#modal-result-value").html("")
    $("#ekyc_last_name").html("");
    $("#ekyc_first_name").html("");
    $("#ekyc_middle_name").html("");
    $("#ekyc_suffix").html("");
    $("#ekyc_dob").html("");
    $("#ekyc_phone_number").html("");
    $("#ekyc_email").html("");
    $("#ekyc_age").html("");
    $("#ekyc_marital_status").html("");
    $("#ekyc_country").html("");
    $("#ekyc_present_address").html("");
    $("#ekyc_province").html("");
    $("#ekyc_municipality").html("");
    $("#ekyc_barangay").html("");
    $("#ekyc_postal_code").html("");
    $("#ekyc_blood_type").html("");
    $("#ekyc_photo").removeAttr("src");
}