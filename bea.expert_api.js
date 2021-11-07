/* **********************

    beA.expert BEA-API / EXPERIMENTAL
    ---------------------------------
    Demo script not intented for production
    Version 1.16 / 05.11.2021
    (c) be next GmbH (Licence: GPL-2.0 & BSD-3-Clause)
    https://opensource.org/licenses/GPL-2.0
    https://opensource.org/licenses/BSD-3-Clause
    

    Dependency: 
    -----------
    Node-Forge (Licence: GPL-2.0 & BSD-3-Clause)
    https://github.com/digitalbazaar/forge

   ********************** */

var bex_ident = "BEX-IDENT";

function encode_utf8(s) {
  return unescape(encodeURIComponent(s));
}

function decode_utf8(s) {
  return decodeURIComponent(escape(s));
}

function getCertificateValues(contents_raw, password) {
  var pkcs12_der;
  var p12_asn1;
  var p12;

  pkcs12_der = forge.util.decode64(btoa(contents_raw));
  p12_asn1 = forge.asn1.fromDer(pkcs12_der);
  p12 = forge.pkcs12.pkcs12FromAsn1(p12_asn1, false, password);

  return {
    pkcs12_der: pkcs12_der,
    p12_asn1: p12_asn1,
    p12: p12,
  };
}

function get_pubKey(cert) {
  var cert_b64 = forge.util.encode64(cert);
  return cert_b64;
}

function get_cert_thumbprint(public_key) {
  const md = forge.md.sha1.create();
  md.update(
    forge.asn1.toDer(forge.pki.certificateToAsn1(public_key)).getBytes()
  );
  return md.digest().toHex();
}

function bea_login_step1(contents, pin_token) {
  var pkcs12_der;
  var p12_asn1;
  var p12;
  var private_key;
  var public_key;
  var cert_thumprint;
  var cert_pubkey;

  var cert_values = getCertificateValues(contents, pin_token);
  pkcs12_der = cert_values.pkcs12_der;
  p12_asn1 = cert_values.p12_asn1;
  p12 = cert_values.p12;

  for (var sci = 0; sci < p12.safeContents.length; ++sci) {
    var safeContents = p12.safeContents[sci];

    for (var sbi = 0; sbi < safeContents.safeBags.length; ++sbi) {
      var safeBag = safeContents.safeBags[sbi];

      if (safeBag.type === forge.pki.oids.keyBag) {
        private_key = safeBag.key;
        console.log("private_key:");
        console.log(private_key);
      } else if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
        private_key = safeBag.key;
        console.log("private_key:");
        console.log(private_key);
      } else if (safeBag.type === forge.pki.oids.certBag) {
        public_key = safeBag.cert;
        console.log("public_key:");
        console.log(public_key);

        cert_thumprint = get_cert_thumbprint(public_key);
        console.log("cert_thumprint:");
        console.log(cert_thumprint);

        cert_pubkey = forge.pki.certificateToPem(public_key);
        console.log("cert_pubkey:");
        console.log(cert_pubkey);
      }
    }
  }

  var next_req = false;
  var login_step1 = "";

  var request = new XMLHttpRequest();
  request.open("POST", "/bea_login_step1", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var data =
    "j=" + encodeURI(btoa('{ "thumbprint": "' + cert_thumprint + '" }'));
  request.send(data);
  if (request.status === 200) {
    login_step1 = request.responseText;
    console.log(login_step1);
    next_req = true;
  }

  var sessionKey = "";
  var safeId = "";
  var error_occured = true;
  var token = "";

  if (next_req) {
    var json_login_step1 = JSON.parse(login_step1);
    if (json_login_step1 != null) {
      var res_login_step2 = bea_login_step2(
        json_login_step1,
        private_key,
        cert_pubkey
      );

      sessionKey = res_login_step2.sessionKey;
      safeId = res_login_step2.safeId;
      error_occured = res_login_step2.error_occured;
      token = res_login_step2.token;
    }
  } else {
    alert("login step1 failed");
  }

  return {
    token: token,
    safeId: safeId,
    sessionKey: sessionKey,
    error_occured: error_occured,
  };
}

function bea_login_step2(json_login_step1, private_key, cert_pubkey) {
  var req2_json_str = "";
  var digestToSign = json_login_step1.challengeVal;
  var digestValidation = json_login_step1.challengeValidation;

  var md = forge.md.sha256.create();
  md.update(atob(digestToSign));
  var signature = forge.util.encode64(private_key.sign(md));

  var md_validation = forge.md.sha256.create();
  md_validation.update(atob(digestValidation));
  var signature_validation = forge.util.encode64(
    private_key.sign(md_validation)
  );

  console.log("signature");
  console.log(signature);

  req2_json_str =
    "{" +
    '"tokenPAOS" : "' +
    json_login_step1.tokenPAOS +
    '",' +
    '"userCert" : "' +
    btoa(cert_pubkey) +
    '",' +
    '"challengeSigned" : "' +
    signature +
    '",' +
    '"validationSigned" : "' +
    signature_validation +
    '"' +
    "}";

  var login_step2 = "";
  var sessionKey = "";
  var validationKey = "";
  var safeId = "";
  var error_occured = true;
  var token = "";

  var request = new XMLHttpRequest();
  request.open("POST", "/bea_login_step2", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var post_data = "j=" + encodeURI(btoa(req2_json_str));
  request.send(post_data);
  if (request.status === 200) {
    login_step2 = request.responseText;
    console.log(login_step2);

    var json_login_step2 = JSON.parse(login_step2);
    if (json_login_step2 != null) {
      var sessionKey_enc = json_login_step2.sessionKey;
      var validationKey_enc = json_login_step2.validationKey;
      var tokenValidation = json_login_step2.tokenValidation;

      validationKey = private_key.decrypt(atob(validationKey_enc), "RSA-OAEP", {
        md: forge.md.sha256.create(),
        mgf1: {
          md: forge.md.sha256.create(),
        },
      });

      sessionKey = private_key.decrypt(atob(sessionKey_enc), "RSA-OAEP", {
        md: forge.md.sha256.create(),
        mgf1: {
          md: forge.md.sha256.create(),
        },
      });

      safeId = json_login_step2.safeId;

      console.log("safeId:");
      console.log(safeId);

      console.log("sessionKey in b64:");
      console.log(btoa(sessionKey));

      token = bea_login_step3(tokenValidation, validationKey);
      error_occured = false;
    }
  } else {
    alert("login step2 failed");
  }

  return {
    token: token,
    safeId: safeId,
    sessionKey: sessionKey,
    error_occured: error_occured,
  };
}

function bea_login_step3(tokenValidation, validationKey) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_login_step3", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str =
    "{" +
    '"tokenValidation" : "' +
    tokenValidation +
    '",' +
    '"validationKey" : "' +
    btoa(validationKey) +
    '"' +
    "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    var json_login_step3 = JSON.parse(res);
    if (json_login_step3 != null) {
      return json_login_step3.token;
    } else {
      return "";
    }
  } else {
    alert("login step3 failed");
  }

  return "";
}

function bea_get_postboxes(token) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_get_postboxes", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str = "{" + '"token" : "' + token + '"' + "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("get_postboxes failed");
  }

  return "";
}

function bea_get_folderoverview(token, folderId, sessionKey) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_get_folderoverview", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str =
    "{" +
    '"token" : "' +
    token +
    '",' +
    '"folderId" : "' +
    folderId +
    '"' +
    "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    if (sessionKey != null) {
      var json_fo = JSON.parse(res);

      if (json_fo != null) {
        var res_dec = {
          messages: [],
        };

        json_fo.messages.forEach((element) => {
          var dec_subject = "";

          if (element.encSubject != null)
            if (element.encSubject.value != null)
              if (element.encSubject.value != "") {
                var decipher = forge.cipher.createDecipher(
                  "AES-GCM",
                  sessionKey
                );
                decipher.start({
                  iv: atob(element.encSubject.iv),
                  tag: atob(element.encSubject.tag),
                });

                decipher.update(
                  forge.util.createBuffer(atob(element.encSubject.value))
                );
                var pass = decipher.finish();

                if (pass) {
                  dec_subject = decode_utf8(decipher.output.data);
                }
              }

          res_dec.messages.push({
            messageId: element.messageId,
            decSubject: dec_subject,
            sender: element.sender,
            addressees: element.addressees,
            zugegangen: element.zugegangen,
            sent: element.sent,
            received: element.received,
            egvpStatus: element.egvpStatus,
            attachments: element.attachments,
            referenceNumber: element.referenceNumber,
            referenceNumberJustice: element.referenceNumberJustice,
            osciSubjectType: element.osciSubjectType,
            deletion: element.deletion,
            urgent: element.urgent,
            checkRequired: element.checkRequired,
            confidential: element.confidential,
            folderId: element.folderId,
            exported: element.exported,
          });
        });
      }
      return JSON.stringify(res_dec);
    } else {
      return res;
    }
  } else {
    alert("get_folderoverview failed");
  }

  return "";
}

function bea_logout(token) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_logout", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str = "{" + '"token" : "' + token + '"' + "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("logout failed");
  }

  return "";
}

function bea_get_folderstructure(token, postboxSafeId) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_get_folderstructure", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str =
    "{" +
    '"token" : "' +
    token +
    '",' +
    '"postboxSafeId" : "' +
    postboxSafeId +
    '"' +
    "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("getFolderStructure failed");
  }

  return "";
}

function bea_get_identitydata(token) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_get_identitydata", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str = "{" + '"token" : "' + token + '"' + "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("getIdentityData failed");
  }

  return "";
}

function bea_get_username(token, identitySafeId) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_get_username", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str =
    "{" +
    '"token" : "' +
    token +
    '",' +
    '"identitySafeId" : "' +
    identitySafeId +
    '"' +
    "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("getUserName failed");
  }

  return "";
}

function bea_add_addressbookentry(token, identitySafeId) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_add_addressbookentry", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str =
    "{" +
    '"token" : "' +
    token +
    '",' +
    '"identitySafeId" : "' +
    identitySafeId +
    '"' +
    "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("addAddressbookEntry failed");
  }

  return "";
}

function bea_get_messageconfig(token) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_get_messageconfig", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str = "{" + '"token" : "' + token + '"' + "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("getMessageConfig failed");
  }

  return "";
}

function bea_get_addressbook(token) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_get_addressbook", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str = "{" + '"token" : "' + token + '"' + "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("getAddressbook failed");
  }

  return "";
}

function bea_delete_addressbookentry(token, addressbookEntrySafeId) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_delete_addressbookentry", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str =
    "{" +
    '"token" : "' +
    token +
    '",' +
    '"addressbookEntrySafeId" : "' +
    addressbookEntrySafeId +
    '"' +
    "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("deleteAddressbookEntry failed");
  }

  return "";
}

function bea_get_message(token, messageId, sessionKey) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_get_message", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str =
    "{" +
    '"token" : "' +
    token +
    '",' +
    '"messageId" : "' +
    messageId +
    '"' +
    "}";

  var post_data = "j=" + encodeURI(btoa(encode_utf8(req_json_str)));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    var json_msg = JSON.parse(res);

    if (json_msg != null) {
      var dec_subject = "";

      if (json_msg.metaData != null)
        if (json_msg.metaData.subject != null)
          if (json_msg.metaData.subject.value != "") {
            var decipher = forge.cipher.createDecipher("AES-GCM", sessionKey);
            decipher.start({
              iv: atob(json_msg.metaData.subject.iv),
              tag: atob(json_msg.metaData.subject.tag),
            });

            decipher.update(
              forge.util.createBuffer(atob(json_msg.metaData.subject.value))
            );
            var pass = decipher.finish();

            if (pass) {
              console.log(decode_utf8(decipher.output.data));
              dec_subject = decode_utf8(decipher.output.data);
            }
          }

      var decryptedObjects = [];
      var attachmentsKey = [];
      json_msg.encryptedObjects.forEach((element) => {
        //decrypt the objectKey with sessionKey
        var objectKey = "";
        var decipher = forge.cipher.createDecipher("AES-GCM", sessionKey);
        decipher.start({
          iv: atob(element.encKeyInfo.encKey.iv),
          tag: atob(element.encKeyInfo.encKey.tag),
        });

        decipher.update(
          forge.util.createBuffer(atob(element.encKeyInfo.encKey.value))
        );
        var pass = decipher.finish();

        if (pass) {
          console.log(decipher.output.data);
          objectKey = decipher.output.data;
        }

        var data = "";

        //decrypt encryptedObject with objectKey
        if (element.enc_iv == "" && element.enc_tag == "") {
          data = decrypt_aes256cbc(element.enc_data, btoa(objectKey));
          if (data != "") {
            pass = true;
          } else {
            pass = false;
          }
        } else {
          decipher = forge.cipher.createDecipher("AES-GCM", objectKey);
          decipher.start({
            iv: atob(element.enc_iv),
            tag: atob(element.enc_tag),
          });

          decipher.update(forge.util.createBuffer(atob(element.enc_data)));
          pass = decipher.finish();
          data = decipher.output.data;
        }

        if (pass) {
          console.log(data);

          decryptedObjects.push({
            name: element.enc_name,
            data: data,
          });

          if (element.enc_name == "project_coco") {
            var parser = new DOMParser();
            var xmlDoc = parser.parseFromString(
              '<?xml version="1.0" encoding="UTF-8"?>' + data,
              "text/xml"
            );
            //var osci_content = xmlDoc.getElementsByTagName("osci:Content");
            var ds_MgmtData = xmlDoc.getElementsByTagName("ds:MgmtData");
            var xenc_CipherReference = xmlDoc.getElementsByTagName(
              "xenc:CipherReference"
            );
            var key_alt = "";

            for (var i = 0; i < xenc_CipherReference.length; i++) {
              var tmp_name = xenc_CipherReference[i].attributes["URI"].value;
              if (tmp_name.substr(0, 4) == "cid:") {
                tmp_name = tmp_name.substr(4);
              }
              var tmp_key = ds_MgmtData[i].textContent;
              if (key_alt == "") {
                key_alt = tmp_key;
              }

              //use same key; if len differs
              if (xenc_CipherReference.length != ds_MgmtData.length) {
                tmp_key = key_alt;
              }

              attachmentsKey.push({
                name: tmp_name,
                key: tmp_key,
              });
            }
          }
        }
      });

      var decryptedAttachments = [];
      json_msg.attachments.forEach((element) => {
        var data = "";
        var att_key = "";

        for (var i = 0; i < attachmentsKey.length; i++) {
          if (attachmentsKey[i].name == element.reference) {
            att_key = atob(attachmentsKey[i].key);
          }
        }

        if (
          element.symEncAlgorithm ==
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc" ||
          (element.iv == "" && element.tag == "")
        ) {
          if (att_key == "") {
            data = decrypt_aes256cbc(element.data, element.key, element.iv);
          } else {
            data = decrypt_aes256cbc(element.data, btoa(att_key), element.iv);
          }
        } else {
          var decipher = forge.cipher.createDecipher("AES-GCM", att_key);
          decipher.start({
            iv: atob(element.iv),
            tag: atob(element.tag),
          });

          decipher.update(forge.util.createBuffer(atob(element.data)));
          var pass = decipher.finish();

          if (pass) {
            data = decipher.output.data;
          }
        }

        decryptedAttachments.push({
          reference: element.reference,
          data: data,
          type: element.type,
          sizeKB: element.sizeKB,
          hashValue: element.hashValue,
        });
      });

      var res_dec = {
        osciSubject: json_msg.osciSubject,
        osciMessageId: json_msg.osciMessageId,
        messageId: json_msg.messageId,
        attachments: decryptedAttachments,
        decryptedObjects: decryptedObjects,

        metaData: {
          created: json_msg.metaData.created,
          receptionTime: json_msg.metaData.receptionTime,
          zugegangen: json_msg.metaData.zugegangen,
          sender: json_msg.metaData.sender,
          addressees: json_msg.metaData.addressees,
          decSubject: dec_subject,
          referenceNumber: json_msg.metaData.referenceNumber,
          referenceJustice: json_msg.metaData.referenceJustice,
          messageSigned: json_msg.metaData.messageSigned,
          oneAttachmentSigned: json_msg.metaData.oneAttachmentSigned,
          urgent: json_msg.metaData.urgent,
          checkRequired: json_msg.metaData.checkRequired,
          confidential: json_msg.metaData.confidential,
          eebAngefordert: json_msg.metaData.eebAngefordert,
          messageStructureType: json_msg.metaData.messageStructureType,
          originatorCertificate: json_msg.metaData.originatorCertificate,
          originatorSignatureCertificate:
            json_msg.metaData.originatorSignatureCertificate,
        },

        newEGVPMessage: json_msg.newEGVPMessage,
        version: json_msg.version,
        symEncAlgorithm: json_msg.symEncAlgorithm,
      };

      console.log(res_dec);
      return JSON.stringify(res_dec);
    } else {
      return res;
    }
  } else {
    alert("getMessage failed");
  }

  return "";
}

function decrypt_aes256cbc(encrypted, key, iv = "") {
  if (encrypted == "") {
    console.log("empty data");
    return "";
  }
  const encoding = "latin1";
  if (iv == "") {
    iv = atob(encrypted).toString(encoding).substring(0, 16);
    encrypted = atob(encrypted).toString(encoding).substring(16);
  } else {
    iv = atob(iv);
    encrypted = atob(encrypted);
  }

  var decipher = forge.cipher.createDecipher("AES-CBC", atob(key));
  decipher.start({ iv: iv });
  decipher.update(forge.util.createBuffer(encrypted));
  var result = decipher.finish();

  if (result) {
    return decipher.output.data;
  }
  //return decipher.output.getBytes();

  return "";
}

function bea_add_folder(token, parentFolderId, newFolderName) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_add_folder", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str =
    "{" +
    '"token" : "' +
    token +
    '",' +
    '"parentFolderId" : "' +
    parentFolderId +
    '",' +
    '"newFolderName" : "' +
    newFolderName +
    '"' +
    "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("addFolder failed");
  }

  return "";
}

function bea_remove_folder(token, folderId) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_remove_folder", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str =
    "{" +
    '"token" : "' +
    token +
    '",' +
    '"folderId" : "' +
    folderId +
    '"' +
    "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("removeFolder failed");
  }

  return "";
}

function bea_move_messagetofolder(token, folderId, messageId) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_move_messagetofolder", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str =
    "{" +
    '"token" : "' +
    token +
    '",' +
    '"folderId" : "' +
    folderId +
    '",' +
    '"messageId" : "' +
    messageId +
    '"' +
    "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("moveMessageToFolder failed");
  }

  return "";
}

function bea_move_messagetotrash(token, messageId) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_move_messagetotrash", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str =
    "{" +
    '"token" : "' +
    token +
    '",' +
    '"messageId" : "' +
    messageId +
    '"' +
    "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("moveMessageToTrash failed");
  }

  return "";
}

function bea_restore_messagefromtrash(token, messageId) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_restore_messagefromtrash", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str =
    "{" +
    '"token" : "' +
    token +
    '",' +
    '"messageId" : "' +
    messageId +
    '"' +
    "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("restoreMessageFromTrash failed");
  }

  return "";
}

function bea_delete_message(token, messageId) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_delete_message", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str =
    "{" +
    '"token" : "' +
    token +
    '",' +
    '"messageId" : "' +
    messageId +
    '"' +
    "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("deleteMessage failed");
  }

  return "";
}

function bea_init_message(token, postboxSafeId, msg_infos, sessionKey) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_init_message", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json_str =
    "{" +
    '"token" : "' +
    token +
    '",' +
    '"postboxSafeId" : "' +
    postboxSafeId +
    '",' +
    '"msg_infos" : ' +
    JSON.stringify(msg_infos) +
    "}";

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    var j = JSON.parse(res);
    var key = "";
    var messageToken = "";

    if (j != null) {
      if (j.key != null)
        if (j.key.value != "") {
          var decipher = forge.cipher.createDecipher("AES-GCM", sessionKey);
          decipher.start({
            iv: atob(j.key.iv),
            tag: atob(j.key.tag),
          });

          decipher.update(forge.util.createBuffer(atob(j.key.value)));
          var pass = decipher.finish();

          if (pass) {
            key = decipher.output.data;
          }

          messageToken = j.messageToken;
        }

      var res_msg_token = {
        messageToken: messageToken,
        key: btoa(key),
      };

      console.log(res_msg_token);
      return JSON.stringify(res_msg_token);
    }

    return res;
  } else {
    alert("initMessage failed");
  }

  return "";
}

function bea_init_message_draft(token, messageId, sessionKey) {
  var request = new XMLHttpRequest();
  request.open("POST", uri_api + "/bea_init_message_draft", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", "loadtest");
  request.setRequestHeader("Access-Control-Allow-Origin", "*");

  var req_json_str =
    "{" +
    '"token" : "' +
    token +
    '",' +
    '"messageId" : "' +
    messageId +
    '"' +
    "}";

  var post_data = "j=" + encodeURI(btoa(encode_utf8(req_json_str)));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    var json_msg = JSON.parse(res);
    var decryptedObjects = [];
    var attachmentsKey = [];
    json_msg.msg_infos.encryptedObjects.forEach((element) => {
      //decrypt the objectKey with sessionKey
      var objectKey = "";
      var decipher = forge.cipher.createDecipher("AES-GCM", sessionKey);
      decipher.start({
        iv: atob(element.encKeyInfo.encKey.iv),
        tag: atob(element.encKeyInfo.encKey.tag),
      });

      decipher.update(
        forge.util.createBuffer(atob(element.encKeyInfo.encKey.value))
      );
      var pass = decipher.finish();

      if (pass) {
        console.log(decipher.output.data);
        objectKey = decipher.output.data;
      }

      var data = "";

      //decrypt encryptedObject with objectKey
      if (element.enc_iv == "" && element.enc_tag == "") {
        data = decrypt_aes256cbc(element.enc_data, btoa(objectKey));
        if (data != "") {
          pass = true;
        } else {
          pass = false;
        }
      } else {
        decipher = forge.cipher.createDecipher("AES-GCM", objectKey);
        decipher.start({
          iv: atob(element.enc_iv),
          tag: atob(element.enc_tag),
        });

        decipher.update(forge.util.createBuffer(atob(element.enc_data)));
        pass = decipher.finish();
        data = decipher.output.data;
      }

      if (pass) {
        console.log(data);

        decryptedObjects.push({
          name: element.enc_name,
          data: data,
        });

        if (element.enc_name == "project_coco") {
          var parser = new DOMParser();
          var xmlDoc = parser.parseFromString(
            '<?xml version="1.0" encoding="UTF-8"?>' + data,
            "text/xml"
          );
          //var osci_content = xmlDoc.getElementsByTagName("osci:Content");
          var ds_MgmtData = xmlDoc.getElementsByTagName("ds:MgmtData");
          var xenc_CipherReference = xmlDoc.getElementsByTagName(
            "xenc:CipherReference"
          );
          var key_alt = "";

          for (var i = 0; i < xenc_CipherReference.length; i++) {
            var tmp_name = xenc_CipherReference[i].attributes["URI"].value;
            if (tmp_name.substr(0, 4) == "cid:") {
              tmp_name = tmp_name.substr(4);
            }
            var tmp_key = ds_MgmtData[i].textContent;
            if (key_alt == "") {
              key_alt = tmp_key;
            }

            //use same key; if len differs
            if (xenc_CipherReference.length != ds_MgmtData.length) {
              tmp_key = key_alt;
            }

            attachmentsKey.push({
              name: tmp_name,
              key: tmp_key,
            });
          }
        }
      }
    });

    json_msg.msg_infos.encryptedObjects = null;

    //Decrypt the attachments
    var decryptedAttachments = [];
    json_msg.msg_infos.attachments.forEach((element) => {
      var data = "";
      var att_key = "";

      for (var i = 0; i < attachmentsKey.length; i++) {
        if (attachmentsKey[i].name == element.reference) {
          att_key = atob(attachmentsKey[i].key);
        }
      }

      if (
        element.symEncAlgorithm ==
          "http://www.w3.org/2001/04/xmlenc#aes256-cbc" ||
        (element.iv == "" && element.tag == "")
      ) {
        if (att_key == "") {
          data = decrypt_aes256cbc(element.data, element.key, element.iv);
        } else {
          data = decrypt_aes256cbc(element.data, btoa(att_key), element.iv);
        }
      } else {
        var decipher = forge.cipher.createDecipher("AES-GCM", att_key);
        decipher.start({
          iv: atob(element.iv),
          tag: atob(element.tag),
        });

        decipher.update(forge.util.createBuffer(atob(element.data)));
        var pass = decipher.finish();

        if (pass) {
          data = decipher.output.data;
        }
      }

      decryptedAttachments.push({
        reference: element.reference,
        data: data,
        type: element.type,
        sizeKB: element.sizeKB,
        hashValue: element.hashValue,
      });
    });

    //Decrypt the key
    var key = "";
    var messageToken = json_msg.messageToken;
    var decipher = forge.cipher.createDecipher("AES-GCM", sessionKey);
    decipher.start({
      iv: atob(json_msg.key.iv),
      tag: atob(json_msg.key.tag),
    });

    decipher.update(forge.util.createBuffer(atob(json_msg.key.value)));
    var pass = decipher.finish();

    if (pass) {
      key = decipher.output.data;
    }

    //Decrypt the subject
    var dec_subject = "";
    if (json_msg.msg_infos.betreff.value != "") {
      var decipher = forge.cipher.createDecipher("AES-GCM", sessionKey);
      decipher.start({
        iv: atob(json_msg.msg_infos.betreff.iv),
        tag: atob(json_msg.msg_infos.betreff.tag),
      });

      decipher.update(
        forge.util.createBuffer(atob(json_msg.msg_infos.betreff.value))
      );
      var pass = decipher.finish();

      if (pass) {
        console.log(decode_utf8(decipher.output.data));
        dec_subject = decode_utf8(decipher.output.data);
      }
    }

    var msg_attachments_data = [];
    var msg_attachments_info = [];
    decryptedAttachments.forEach((element) => {
      msg_attachments_data.push({
        name: element.reference,
        data: btoa(element.data),
        att_type: element.type,
      });
      msg_attachments_info.push(element.reference);
    });

    //get receivers
    var new_receivers = [];
    json_msg.receivers_full = [];
    if (
      json_msg.msg_infos != null &&
      json_msg.msg_infos != undefined &&
      json_msg.msg_infos.receivers != null &&
      json_msg.msg_infos.receivers != undefined &&
      json_msg.msg_infos.receivers.length != 0
    ) {
      json_msg.msg_infos.receivers.forEach((element) => {
        new_receivers.push(element.safeId);
      });

      json_msg.receivers = new_receivers;
    }

    json_msg.msg_infos.betreff = dec_subject;
    json_msg.msg_infos.attachments = msg_attachments_info;
    json_msg.key = btoa(key);
    json_msg.msg_attachments_data = msg_attachments_data;

    //Important: get msg_text and read xjustiz to complete the infos
    console.warn(JSON.stringify(json_msg));
    return JSON.stringify(json_msg);
  }
}

function bea_encrypt_message(
  token,
  postboxSafeId,
  msg_infos,
  msg_att,
  sessionKey
) {
  var res_init_msg = bea_init_message(
    token,
    postboxSafeId,
    msg_infos,
    sessionKey
  );

  if (res_init_msg != "") {
    var encSubject;
    var enc_attachment_data = [];
    var j = JSON.parse(res_init_msg);

    if (j != null) {
      var tmp_data;
      tmp_data = encrypt_aes256gcm(msg_infos.betreff, atob(j.key));
      encSubject = {
        data: tmp_data.data,
        tag: tmp_data.tag,
        iv: tmp_data.iv,
        key: j.key,
      };
      console.log(encSubject);

      for (var i = 0; i < msg_att.attachments.length; i++) {
        tmp_data = encrypt_aes256gcm(
          atob(msg_att.attachments[i].data),
          atob(j.key)
        );

        var md = forge.md.sha256.create();
        md.update(atob(msg_att.attachments[i].data), "utf8");

        enc_attachment_data.push({
          data: tmp_data.data,
          tag: tmp_data.tag,
          iv: tmp_data.iv,
          key: j.key,
          name: msg_att.attachments[i].name,
          sizeKB: parseInt(msg_att.attachments[i].data.length / 1024, 10), //size in KB!
          hash: btoa(md.digest().data),
          att_type: msg_att.attachments[i].att_type,
        });
      }

      var req_json = {
        messageToken: j.messageToken,
        encrypted_data: {
          encSubject: encSubject,
          attachments: enc_attachment_data,
        },
      };
      console.log(JSON.stringify(req_json));

      return req_json;
    }
  } else {
    alert("initMessage failed");
  }

  return "";
}

export function bea_cleanup_message(messageToken) {
  var req_json = {
    messageToken: messageToken,
  };
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_cleanup_message", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

  //var post_data = 'j=' + encodeURI(btoa(JSON.stringify(req_json)));
  var post_data = "j=" + encodeURI(btoa(encode_utf8(JSON.stringify(req_json))));
  request.send(post_data);
  if (request.status === 200) {
    return request.responseText;
  } else {
    alert("bea_cleanup_message failed");
  }

  return "";
}

function bea_save_message(
  token,
  postboxSafeId,
  msg_infos,
  msg_att,
  sessionKey
) {
  var req_json = bea_encrypt_message(
    token,
    postboxSafeId,
    msg_infos,
    msg_att,
    sessionKey
  );

  var request = new XMLHttpRequest();
  request.open("POST", "/bea_save_message", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var post_data = "j=" + encodeURI(btoa(JSON.stringify(req_json)));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("saveMessage failed");
  }

  return "";
}

function bea_send_message(
  token,
  postboxSafeId,
  msg_infos,
  msg_att,
  sessionKey
) {
  var req_json = bea_encrypt_message(
    token,
    postboxSafeId,
    msg_infos,
    msg_att,
    sessionKey
  );

  var request = new XMLHttpRequest();
  request.open("POST", "/bea_send_message", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var post_data = "j=" + encodeURI(btoa(JSON.stringify(req_json)));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    var j = JSON.parse(res);

    if (j != null) {
      res = bea_send_message_validation(
        j.validationTokenMSG,
        j.validations,
        sessionKey
      );
    }

    return res;
  } else {
    alert("sendMessage failed");
  }

  return "";
}

function bea_send_message_validation(
  validationTokenMSG,
  validations,
  sessionKey
) {
  var dec_validations = [];
  if (validations != null)
    for (var i = 0; i < validations.length; i++) {
      var decipher = forge.cipher.createDecipher("AES-GCM", sessionKey);
      decipher.start({
        iv: atob(validations[i].iv),
        tag: atob(validations[i].tag),
      });

      decipher.update(forge.util.createBuffer(atob(validations[i].data)));
      var pass = decipher.finish();

      if (pass) {
        dec_validations.push({
          data: btoa(decipher.output.data),
          id: validations[i].id,
        });
      }
    }

  var request = new XMLHttpRequest();
  request.open("POST", "/bea_send_message_validation", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", bex_ident);

  var req_json = {
    validationTokenMSG: validationTokenMSG,
    validations: dec_validations,
  };

  var post_data = "j=" + encodeURI(btoa(JSON.stringify(req_json)));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("sendMessage failed");
  }

  return "";
}

function encrypt_aes256gcm(input, key) {
  var iv = forge.random.getBytesSync(16);
  var cipher = forge.cipher.createCipher("AES-GCM", key);
  cipher.start({
    iv: iv,
  });
  cipher.update(forge.util.createBuffer(input));
  cipher.finish();

  var encrypted = cipher.output;
  var tag = cipher.mode.tag;

  return {
    data: btoa(encrypted.data),
    tag: btoa(tag.data),
    iv: btoa(iv),
  };
}

function demo_get_my_bea_inbox() {
  document.getElementById("logger").innerHTML = "";
  document.getElementById("spinner1").style.visibility = "visible";
  document.getElementById("spinner2").style.visibility = "visible";
  var inbox = document.getElementById("inbox");
  inbox.innerHTML = "";

  var reader = new FileReader();
  var contents;

  reader.onload = function () {
    contents = reader.result;
    var login_res = "";
    var sessionKey = "";
    var safeId = "";
    var token = "";

    const pin_token = document.getElementById("pinToken");

    try {
      login_res = bea_login_step1(contents, pin_token.value);
    } catch (e) {
      alert("Could not load P12");
      login_res = { error_occured: true };
    }

    if (!login_res.error_occured) {
      sessionKey = login_res.sessionKey;
      safeId = login_res.safeId;
      token = login_res.token;

      var res_postboxes = bea_get_postboxes(token);

      var json_res_postboxes = JSON.parse(res_postboxes);
      if (json_res_postboxes != null) {
        var folderId = "";

        json_res_postboxes.postboxes.forEach((element) => {
          element.folder.forEach((e_folder) => {
            if (e_folder.type == "INBOX" && e_folder.postboxSafeId == safeId) {
              folderId = e_folder.id;
            }
          });
        });

        var res_inbox_overview = bea_get_folderoverview(
          token,
          folderId,
          sessionKey
        );

        var json_res_inbox_overview = JSON.parse(res_inbox_overview);
        json_res_inbox_overview.messages.forEach((element) => {
          inbox.innerHTML +=
            "<b>--- Message id:" + element.messageId + " -------------</b><br>";
          inbox.innerHTML +=
            "From: " +
            element.sender.surname +
            ", " +
            element.sender.firstname +
            " (" +
            element.sender.postalcode +
            " " +
            element.sender.city +
            ")<br>";
          inbox.innerHTML += "<i>Subject: " + element.decSubject + "</i><br>";
        });
      } else {
        alert("get_postboxes json parsing failed");
      }
    }
    document.getElementById("spinner1").style.visibility = "hidden";
    document.getElementById("spinner2").style.visibility = "hidden";
  };

  const f = document.getElementById("theToken");
  reader.readAsBinaryString(f.files[0]);
}

function send_test_message(token, safeId, sessionKey) {
  var msg_infos = {
    betreff: "this is a test message",
    aktz_sender: "test message",
    aktz_rcv: "test message",
    msg_text: "This is a simple test message.",
    is_eeb: false,
    dringend: false,
    pruefen: false,
    receivers: ["DE.Justiztest.dd380ae8-10f8-4b5f-8dce-e54b80722409.a80d"], //for saveMessage, the receivers should be empty
    attachments: ["myText1.txt"], //only the attachments names
    is_eeb_response: false,
    eeb_fremdid: "",
    eeb_date: "",
    verfahrensgegenstand: "",
    eeb_erforderlich: false,
    eeb_accept: false,
    xj: false,
    nachrichten_typ: "ALLGEMEINE_NACHRICHT",
  };

  var msg_att = {
    attachments: [
      {
        name: "myText1.txt", // attachment name, should be unique
        data: "TXkgdGV4dCAx", // Raw binary data in b64
        att_type: "SCHRIFTSATZ", // "ATTACHMENT" or "SCHRIFTSATZ"
      },
    ],
  };

  var res_sendMessage = bea_send_message(
    token,
    safeId,
    msg_infos,
    msg_att,
    sessionKey
  );
}

function bea_search(
  token,
  identitySafeId = "",
  identityStatus = "",
  identityType = "",
  identityUsername = "",
  identityFirstname = "",
  identitySurname = "",
  identityPostalcode = "",
  identityCity = "",
  identityChamberType = "",
  identityChamberMembershipId = "",
  identityOfficeName = ""
) {
  var request = new XMLHttpRequest();
  request.open("POST", "/bea_search", false);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.setRequestHeader("bex-ident", "loadtest");
  request.setRequestHeader("Access-Control-Allow-Origin", "*");

  var req_json_str =
    "{" +
    '"token" : "' +
    token +
    '",' +
    '"identitySafeId": "' +
    identitySafeId +
    '",' +
    '"identityStatus": "' +
    identityStatus +
    '",' +
    '"identityType": "' +
    identityType +
    '",' +
    '"identityUsername": "' +
    identityUsername +
    '",' +
    '"identityFirstname": "' +
    identityFirstname +
    '",' +
    '"identitySurname": "' +
    identitySurname +
    '",' +
    '"identityPostalcode": "' +
    identityPostalcode +
    '",' +
    '"identityCity": "' +
    identityCity +
    '",' +
    '"identityChamberType": "' +
    identityChamberType +
    '",' +
    '"identityChamberMembershipId": "' +
    identityChamberMembershipId +
    '",' +
    '"identityOfficeName": "' +
    identityOfficeName +
    '"' +
    "}";

  console.log("req_json_str: ", req_json_str);

  var post_data = "j=" + encodeURI(btoa(req_json_str));
  request.send(post_data);
  if (request.status === 200) {
    var res = request.responseText;
    console.log(res);

    return res;
  } else {
    alert("bea_search failed");
  }

  return "";
}

function send_xjustiz_message(token, safeId, sessionKey) {
  var msg_infos = {
    betreff: "this is a test message",
    aktz_sender: "test message",
    aktz_rcv: "test message",
    msg_text: "This is a simple test message.",
    is_eeb: false,
    dringend: false,
    pruefen: false,
    receivers: ["DE.Justiztest.dd380ae8-10f8-4b5f-8dce-e54b80722409.a80d"], //for saveMessage, the receivers should be empty
    attachments: ["myText1.txt"], //only the attachments names
    is_eeb_response: false,
    eeb_fremdid: "",
    eeb_date: "",
    verfahrensgegenstand: "",
    eeb_erforderlich: false,
    eeb_accept: false,
    xj: true,
    nachrichten_typ: "ALLGEMEINE_NACHRICHT",
  };

  var msg_att = {
    attachments: [
      {
        name: "myText1.txt", // attachment name, should be unique
        data: "TXkgdGV4dCAx", // Raw binary data in b64
        att_type: "SCHRIFTSATZ", // "ATTACHMENT" or "SCHRIFTSATZ"
      },
    ],
  };

  var res_sendMessage = bea_send_message(
    token,
    safeId,
    msg_infos,
    msg_att,
    sessionKey
  );
}

function send_eeb_request_message(token, safeId, sessionKey) {
  var msg_infos_eeb1 = {
    betreff: "eeb anfordern",
    aktz_sender: "test message",
    aktz_rcv: "test message",
    msg_text: "This is a simple test message.",
    is_eeb: false,
    dringend: false,
    pruefen: false,
    receivers: ["DE.BRAK_SPT.fef807c5-d2dd-477d-8571-d02413878789.d5b7"],
    attachments: ["myText1.txt"],
    is_eeb_response: false,
    eeb_fremdid: "",
    eeb_date: "",
    verfahrensgegenstand: "",
    eeb_erforderlich: true,
    eeb_accept: false,
    xj: true,
    nachrichten_typ: "ALLGEMEINE_NACHRICHT",
  };

  var msg_att = {
    attachments: [
      {
        name: "myText1.txt", // attachment name, should be unique
        data: "TXkgdGV4dCAx", // Raw binary data in b64
        att_type: "SCHRIFTSATZ", // "ATTACHMENT" or "SCHRIFTSATZ"
      },
    ],
  };

  var res_sendMessage_eeb_anfordern = bea_send_message(
    token,
    safeId,
    msg_infos_eeb1,
    msg_att,
    sessionKey
  );
}

function send_eeb_accept_message(token, safeId, sessionKey) {
  var msg_infos_eeb3 = {
    betreff: "eeb antworten (accept)",
    aktz_sender: "test message",
    aktz_rcv: "test message",
    msg_text: "This is a simple test message.",
    is_eeb: true,
    dringend: false,
    pruefen: false,
    receivers: ["DE.BRAK_SPT.fef807c5-d2dd-477d-8571-d02413878789.d5b7"],
    attachments: [""],
    is_eeb_response: true,
    eeb_fremdid: "fremdId",
    eeb_date: "", //use server time
    verfahrensgegenstand: "",
    eeb_erforderlich: false,
    eeb_accept: true,
    xj: false,
    nachrichten_typ: "ALLGEMEINE_NACHRICHT",
  };

  var msg_att = {
    attachments: [],
  };

  var res_sendMessage_eeb_accept = bea_send_message(
    token,
    safeId,
    msg_infos_eeb3,
    msg_att,
    sessionKey
  );
}

function send_eeb_reject_message(token, safeId, sessionKey) {
  var msg_infos_eeb2 = {
    betreff: "eeb antworten (ablehnen)",
    aktz_sender: "test message",
    aktz_rcv: "test message",
    msg_text: "This is a simple test message.",
    is_eeb: true,
    dringend: false,
    pruefen: false,
    receivers: ["DE.BRAK_SPT.fef807c5-d2dd-477d-8571-d02413878789.d5b7"],
    attachments: [""],
    is_eeb_response: true,
    eeb_fremdid: "fremdId",
    eeb_date: "", //use server time
    verfahrensgegenstand: "",
    eeb_erforderlich: false,
    eeb_accept: false,
    xj: false,
    nachrichten_typ: "ALLGEMEINE_NACHRICHT",
  };

  var msg_att = {
    attachments: [],
  };

  var res_sendMessage_eeb_ablehnen = bea_send_message(
    token,
    safeId,
    msg_infos_eeb2,
    msg_att,
    sessionKey
  );
}

function send_allgemeine_nachricht_message(token, safeId, sessionKey) {
  var msg_infos_an = {
    betreff: "ALLGEMEINE NACHRICHT",
    aktz_sender: "test message",
    aktz_rcv: "test message",
    msg_text: "This is a simple test message.",
    is_eeb: false,
    dringend: false,
    pruefen: false,
    receivers: ["DE.BRAK_SPT.fef807c5-d2dd-477d-8571-d02413878789.d5b7"],
    attachments: ["myText1.txt"],
    is_eeb_response: false,
    eeb_fremdid: "",
    eeb_date: "",
    verfahrensgegenstand: "",
    eeb_erforderlich: false,
    eeb_accept: false,
    xj: false,
    nachrichten_typ: "ALLGEMEINE_NACHRICHT",
  };

  var msg_att = {
    attachments: [
      {
        name: "myText1.txt", // attachment name, should be unique
        data: "TXkgdGV4dCAx", // Raw binary data in b64
        att_type: "SCHRIFTSATZ", // "ATTACHMENT" or "SCHRIFTSATZ"
      },
    ],
  };

  var res_sendMessage_alg_n = bea_send_message(
    token,
    safeId,
    msg_infos_an,
    msg_att,
    sessionKey
  );
}

function send_mahn_antrag_message(token, safeId, sessionKey) {
  var msg_infos_an = {
    betreff: "MAHN ANTRAG",
    aktz_sender: "test message",
    aktz_rcv: "test message",
    msg_text: "This is a simple test message.",
    is_eeb: false,
    dringend: false,
    pruefen: false,
    receivers: ["DE.BRAK_SPT.fef807c5-d2dd-477d-8571-d02413878789.d5b7"],
    attachments: ["myText1.txt"],
    is_eeb_response: false,
    eeb_fremdid: "",
    eeb_date: "",
    verfahrensgegenstand: "",
    eeb_erforderlich: false,
    eeb_accept: false,
    xj: true,
    nachrichten_typ: "MAHN_ANTRAG",
  };

  var msg_att = {
    attachments: [
      {
        name: "myText1.txt", // attachment name, should be unique
        data: "TXkgdGV4dCAx", // Raw binary data in b64
        att_type: "SCHRIFTSATZ", // "ATTACHMENT" or "SCHRIFTSATZ"
      },
    ],
  };

  var res_sendMessage_alg_n = bea_send_message(
    token,
    safeId,
    msg_infos_an,
    msg_att,
    sessionKey
  );
}

function send_test_nachricht_message(token, safeId, sessionKey) {
  var msg_infos_an = {
    betreff: "TESTNACHRICHT",
    aktz_sender: "test message",
    aktz_rcv: "test message",
    msg_text: "This is a simple test message.",
    is_eeb: false,
    dringend: false,
    pruefen: false,
    receivers: ["DE.BRAK_SPT.fef807c5-d2dd-477d-8571-d02413878789.d5b7"],
    attachments: ["myText1.txt"],
    is_eeb_response: false,
    eeb_fremdid: "",
    eeb_date: "",
    verfahrensgegenstand: "",
    eeb_erforderlich: false,
    eeb_accept: false,
    xj: false,
    nachrichten_typ: "TESTNACHRICHT",
  };

  var msg_att = {
    attachments: [
      {
        name: "myText1.txt", // attachment name, should be unique
        data: "TXkgdGV4dCAx", // Raw binary data in b64
        att_type: "SCHRIFTSATZ", // "ATTACHMENT" or "SCHRIFTSATZ"
      },
    ],
  };

  var res_sendMessage_alg_n = bea_send_message(
    token,
    safeId,
    msg_infos_an,
    msg_att,
    sessionKey
  );
}

function example_edit_message(token, safeId, sessionKey) {
  var msg_infos_draft = {
    betreff: "Subject saveMessage",
    aktz_sender: "sender",
    aktz_rcv: "rcv",
    msg_text: "This is a simple test message.",
    is_eeb: false,
    dringend: false,
    pruefen: false,
    receivers: ["DE.Justiztest.dd380ae8-10f8-4b5f-8dce-e54b80722409.a80d"],
    attachments: ["myText1.txt"],
    is_eeb_response: false,
    eeb_fremdid: "",
    eeb_date: "",
    verfahrensgegenstand: "",
    eeb_erforderlich: false,
    eeb_accept: false,
    xj: true,
    nachrichten_typ: "ALLGEMEINE_NACHRICHT",
  };

  var msg_att = {
    attachments: [
      {
        name: "myText1.txt",
        data: "TXkgdGV4dCAx",
        att_type: "",
      },
    ],
  };

  var res_saveMessage = bea_save_message(
    token,
    safeId,
    msg_infos_draft,
    msg_att,
    sessionKey
  );
  var json_save_msg = JSON.parse(res_saveMessage);
  var init_draft_message = bea_init_message_draft(
    token,
    json_save_msg.messageId,
    sessionKey
  );
  var init_draft_message_json = JSON.parse(init_draft_message);

  var draft_msg_infos = init_draft_message_json.msg_infos;
  var draft_attachments = {
    attachments: init_draft_message_json.msg_attachments_data,
  };
  var messageDraft = JSON.stringify({
    key: init_draft_message_json.key,
    messageToken: init_draft_message_json.messageToken,
  });

  draft_msg_infos.betreff = "Subject sendMessage";
  draft_msg_infos.msg_text = "Message edited.";
  draft_msg_infos.receivers = [
    "DE.Justiztest.dd380ae8-10f8-4b5f-8dce-e54b80722409.a80d",
  ];
  var res_draft_sendMessage = bea_send_message(
    token,
    safeId,
    draft_msg_infos,
    draft_attachments,
    sessionKey,
    messageDraft
  );
  console.warn(res_draft_sendMessage);
  return;
}
