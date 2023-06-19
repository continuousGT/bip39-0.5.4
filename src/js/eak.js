(function() {

    var networksName = "BTC - Bitcoin";
    // mnemonics is populated as required by getLanguage
    var mnemonics = { "english": new Mnemonic("english") };
    var mnemonic = mnemonics["english"];
    var seed = null;
    var bip32RootKey = null;
    var bip32ExtendedKey = null;
    var network = libs.bitcoin.networks.bitcoin;



    var generationProcesses = [];

    var DOM = {};

    var DOM_useOwnEntropy = false; // DOM.useEntropy = $(".use-entropy");

    var DOM_entropy_val = "4187a8bfd9";

    var DOM_entropyTypeInputs_val = "hexadecimal";  // "binary" "base 6" "dice" "base 10" "card"

    var DOM_entropyEventCount = "0";

    var DOM_entropyBits = "0";

    var DOM_entropyBitsPerEvent = "0";

    var DOM_entropyWordCount = "0";

    var DOM_entropyMnemoicLength = "raw";

    var DOM_phrase_val = "";

    var DOM_passphrase_val = "";

    DOM.generate = $(".generate");

    var DOM_seed_val = "";

    var DOM_rootKey_val = "";

    var DOM_extendedPrivKey = "";
    var DOM_extendedPubKey = "";

    var DOM_bip44path_val = "";

    var DOM_bip44purpose_val = 44;

    var DOM_bip44coin_val = 0;

    var DOM_bip44account_val = 0;

    var DOM_bip44accountXprv_val ="";

    var DOM_bip44accountXpub_val = "";

    var DOM_bip44change_val = 0;

    var DOM_generatedStrength = "15";


    var DOM_rowsToAdd_val = "20";   // no of address generated

// initial value for coin network
    setHdCoin(0); // for bitcoin network

    function init() {

        DOM.generate.on("click", generateClicked);

        disableForms();


    }



    function phraseChanged() {

        setMnemonicLanguage();
        // Get the mnemonic phrase
        var phrase = DOM_phrase_val; //DOM.phrase.val();
        var errorText = findPhraseErrors(phrase);
        if (errorText) {
            showValidationError(errorText);
            return;
        }
        // Calculate and display
        var passphrase = DOM_passphrase_val; //DOM.passphrase.val();
        calcBip32RootKeyFromSeed(phrase, passphrase);
        calcForDerivationPath();

    }



    function calcForDerivationPath() {
        clearDerivedKeys();
        clearAddressesList();

        // Get the derivation path
        var derivationPath = getDerivationPath();
        var errorText = findDerivationPathErrors(derivationPath);
        if (errorText) {
            //showValidationError(errorText);
            return;
        }
        bip32ExtendedKey = calcBip32ExtendedKey(derivationPath);
        if (bip44TabSelected()) {
            displayBip44Info();
        }

        displayBip32Info();
    }

    function generateClicked() {
        if (DOM_useOwnEntropy) {
            return;
        }
        clearDisplay();
        //showPending();
        setTimeout(function() {
            setMnemonicLanguage();
            var phrase = generateRandomPhrase();
            if (!phrase) {
                return;
            }
            phraseChanged();
        }, 50);
    }



    // Private methods

    function generateRandomPhrase() {
        if (!hasStrongRandom()) {
            var errorText = "This browser does not support strong randomness";
            //showValidationError(errorText);
            return;
        }
        // get the amount of entropy to use
        var numWords = parseInt(DOM_generatedStrength);
        var strength = numWords / 3 * 32;
        var buffer = new Uint8Array(strength / 8);
        // create secure entropy
        var data = crypto.getRandomValues(buffer);
        // show the words
        var words = mnemonic.toMnemonic(data);
        DOM_phrase_val = words; //DOM.phrase.val(words);
        console.log(DOM_phrase_val);
        // show the entropy
        var entropyHex = uint8ArrayToHex(data);
        DOM_entropy_val = entropyHex; //DOM.entropy.val(entropyHex);
        // ensure entropy fields are consistent with what is being displayed
        DOM_entropyMnemoicLength = "raw"; // DOM.entropyMnemonicLength.val("raw");
        return words;
    }

    function calcBip32RootKeyFromSeed(phrase, passphrase) {
        seed = mnemonic.toSeed(phrase, passphrase);
        bip32RootKey = libs.bitcoin.HDNode.fromSeedHex(seed, network);


    }




    function calcBip32ExtendedKey(path) {
        // Check there's a root key to derive from
        if (!bip32RootKey) {
            return bip32RootKey;
        }
        var extendedKey = bip32RootKey;
        // Derive the key from the path
        var pathBits = path.split("/");
        for (var i=0; i<pathBits.length; i++) {
            var bit = pathBits[i];
            var index = parseInt(bit);
            if (isNaN(index)) {
                continue;
            }
            var hardened = bit[bit.length-1] == "'";
            var isPriv = !(extendedKey.isNeutered());
            var invalidDerivationPath = hardened && !isPriv;
            if (invalidDerivationPath) {
                extendedKey = null;
            }
            else if (hardened) {
                extendedKey = extendedKey.deriveHardened(index);
            }
            else {
                extendedKey = extendedKey.derive(index);
            }
        }
        return extendedKey;
    }



    function findPhraseErrors(phrase) {
        // Preprocess the words
        phrase = mnemonic.normalizeString(phrase);
        var words = phraseToWordArray(phrase);
        // Detect blank phrase
        if (words.length == 0) {
            return "Blank mnemonic";
        }
        // Check each word
        for (var i=0; i<words.length; i++) {
            var word = words[i];
            var language = getLanguage();
            if (WORDLISTS[language].indexOf(word) == -1) {
                console.log("Finding closest match to " + word);
                var nearestWord = findNearestWord(word);
                return word + " not in wordlist, did you mean " + nearestWord + "?";
            }
        }
        // Check the words are valid
        var properPhrase = wordArrayToPhrase(words);
        var isValid = mnemonic.check(properPhrase);
        if (!isValid) {
            return "Invalid mnemonic";
        }
        return false;
    }



    function getDerivationPath() {
        if (bip44TabSelected()) {
            //var purpose = parseIntNoNaN(DOM.bip44purpose.val(), 44);
            var purpose = parseIntNoNaN(DOM_bip44purpose_val,44);
            //var coin = parseIntNoNaN(DOM.bip44coin.val(), 0);
            var coin = parseIntNoNaN(DOM_bip44coin_val, 0);
            //var account = parseIntNoNaN(DOM.bip44account.val(), 0);
            var account = parseIntNoNaN(DOM_bip44account_val, 0);
            var change = parseIntNoNaN(DOM_bip44change_val, 0);
            var path = "m/";
            path += purpose + "'/";
            path += coin + "'/";
            path += account + "'/";
            path += change;
            DOM_bip44path_val = path; // DOM.bip44path.val(path);
            var derivationPath = DOM_bip44path_val; // DOM.bip44path.val();
            console.log("Using derivation path from BIP44 tab: " + derivationPath);
            return derivationPath;
        }

        else {
            console.log("Unknown derivation path");
        }
    }

    function findDerivationPathErrors(path) {
        // TODO is not perfect but is better than nothing
        // Inspired by
        // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
        // and
        // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#extended-keys
        var maxDepth = 255; // TODO verify this!!
        var maxIndexValue = Math.pow(2, 31); // TODO verify this!!
        if (path[0] != "m") {
            return "First character must be 'm'";
        }
        if (path.length > 1) {
            if (path[1] != "/") {
                return "Separator must be '/'";
            }
            var indexes = path.split("/");
            if (indexes.length > maxDepth) {
                return "Derivation depth is " + indexes.length + ", must be less than " + maxDepth;
            }
            for (var depth = 1; depth<indexes.length; depth++) {
                var index = indexes[depth];
                var invalidChars = index.replace(/^[0-9]+'?$/g, "")
                if (invalidChars.length > 0) {
                    return "Invalid characters " + invalidChars + " found at depth " + depth;
                }
                var indexValue = parseInt(index.replace("'", ""));
                if (isNaN(depth)) {
                    return "Invalid number at depth " + depth;
                }
                if (indexValue > maxIndexValue) {
                    return "Value of " + indexValue + " at depth " + depth + " must be less than " + maxIndexValue;
                }
            }
        }
        // Check root key exists or else derivation path is useless!
        if (!bip32RootKey) {
            return "No root key";
        }

        return false;
    }




    function displayBip44Info() {
        // Get the derivation path for the account
        // var purpose = parseIntNoNaN(DOM.bip44purpose.val(), 44);
        var purpose = parseIntNoNaN(DOM_bip44purpose_val,44);
        //var coin = parseIntNoNaN(DOM.bip44coin.val(), 0);
        var coin = parseIntNoNaN(DOM_bip44coin_val, 0);
        //var account = parseIntNoNaN(DOM.bip44account.val(), 0);
        var account = parseIntNoNaN(DOM_bip44account_val, 0);
        var path = "m/";
        path += purpose + "'/";
        path += coin + "'/";
        path += account + "'/";
        // Calculate the account extended keys
        var accountExtendedKey = calcBip32ExtendedKey(path);
        var accountXprv = accountExtendedKey.toBase58();
        var accountXpub = accountExtendedKey.neutered().toBase58();

        // Display the extended keys
        DOM_bip44accountXprv_val = accountXprv;//DOM.bip44accountXprv.val(accountXprv);
        DOM_bip44accountXpub_val = accountXpub;//DOM.bip44accountXpub.val(accountXpub);


    }


    function displayBip32Info() {
        // Display the key
        DOM_seed_val = seed; // DOM.seed.val(seed);
        console.log(DOM_seed_val);
        var rootKey = bip32RootKey.toBase58();
        DOM_rootKey_val= rootKey; // DOM.rootKey.val(rootKey);
        var xprvkeyB58 = "NA";
        if (!bip32ExtendedKey.isNeutered()) {
            xprvkeyB58 = bip32ExtendedKey.toBase58();
        }
        var extendedPrivKey = xprvkeyB58;
        DOM_extendedPrivKey = extendedPrivKey; //DOM.extendedPrivKey.val(extendedPrivKey);
        var extendedPubKey = bip32ExtendedKey.neutered().toBase58();
        DOM_extendedPubKey = extendedPubKey; //DOM.extendedPubKey.val(extendedPubKey);
        console.log(DOM_extendedPubKey);
        // Display the addresses and privkeys
        clearAddressesList();
        //var initialAddressCount = parseInt(DOM.rowsToAdd.val());
        var initialAddressCount = parseInt(DOM_rowsToAdd_val);
        displayAddresses(0, initialAddressCount);

    }

    function displayAddresses(start, total) {
        generationProcesses.push(new (function() {

            var rows = [];

            this.stop = function() {
                for (var i=0; i<rows.length; i++) {
                    rows[i].shouldGenerate = false;
                }
                //hidePending();
            }

            for (var i=0; i<total; i++) {
                var index = i + start;
                var isLast = i == total - 1;
                rows.push(new TableRow(index, isLast));
            }

        })());
    }



    function TableRow(index, isLast) {

        var self = this;
        this.shouldGenerate = true;
        //var useHardenedAddresses = DOM.hardenedAddresses.prop("checked");
        //var useBip38 = DOM.useBip38.prop("checked");
        //var bip38password = DOM.bip38Password.val();
        //var isSegwit = segwitSelected();
        //var segwitAvailable = networkHasSegwit();
        //var isP2wpkh = p2wpkhSelected();
        //var isP2wpkhInP2sh = p2wpkhInP2shSelected();
        //var isP2wsh = p2wshSelected();
        //var isP2wshInP2sh = p2wshInP2shSelected();

        function init() {
            calculateValues();
        }

        function calculateValues() {
            setTimeout(function() {
                if (!self.shouldGenerate) {
                    return;
                }
                // derive HDkey for this row of the table
                var key = "NA";
                /*if (useHardenedAddresses) {
                    key = bip32ExtendedKey.deriveHardened(index);
                }
                else {
                    key = bip32ExtendedKey.derive(index);
                }*/
                key = bip32ExtendedKey.derive(index);
                // bip38 requires uncompressed keys
                // see https://github.com/iancoleman/bip39/issues/140#issuecomment-352164035
                var keyPair = key.keyPair;
                /*var useUncompressed = useBip38;
                if (useUncompressed) {
                    keyPair = new libs.bitcoin.ECPair(keyPair.d, null, { network: network, compressed: false });


                }*/
                // get address
                var address = keyPair.getAddress().toString();
                // get privkey
                var hasPrivkey = !key.isNeutered();
                var privkey = "NA";
                if (hasPrivkey) {
                    privkey = keyPair.toWIF();
                    // BIP38 encode private key if required
                    /*if (useBip38) {

                            privkey = libs.bip38.encrypt(keyPair.d.toBuffer(), false, bip38password, function(p) {
                                console.log("Progressed " + p.percent.toFixed(1) + "% for index " + index);
                            });
                    }*/
                }
                // get pubkey
                var pubkey = keyPair.getPublicKeyBuffer().toString('hex');
                var indexText = getDerivationPath() + "/" + index;
                console.log(address);
                /*if (useHardenedAddresses) {
                    indexText = indexText + "'";
                }*/
                // Ethereum values are different
                if (networkIsEthereum()) {
                    var pubkeyBuffer = keyPair.getPublicKeyBuffer();
                    var ethPubkey = libs.ethUtil.importPublic(pubkeyBuffer);
                    var addressBuffer = libs.ethUtil.publicToAddress(ethPubkey);
                    var hexAddress = addressBuffer.toString('hex');
                    var checksumAddress = libs.ethUtil.toChecksumAddress(hexAddress);
                    address = libs.ethUtil.addHexPrefix(checksumAddress);
                    pubkey = libs.ethUtil.addHexPrefix(pubkey);
                    if (hasPrivkey) {
                        privkey = libs.ethUtil.bufferToHex(keyPair.d.toBuffer(32));
                    }
                }
                //TRX is different
                if (networksName == "TRX - Tron") {
                    keyPair = new libs.bitcoin.ECPair(keyPair.d, null, { network: network, compressed: false });
                    var pubkeyBuffer = keyPair.getPublicKeyBuffer();
                    var ethPubkey = libs.ethUtil.importPublic(pubkeyBuffer);
                    var addressBuffer = libs.ethUtil.publicToAddress(ethPubkey);
                    address = libs.bitcoin.address.toBase58Check(addressBuffer, 0x41);
                    if (hasPrivkey) {
                        privkey = keyPair.d.toBuffer().toString('hex');
                    }
                }

                // RSK values are different
                if (networkIsRsk()) {
                    var pubkeyBuffer = keyPair.getPublicKeyBuffer();
                    var ethPubkey = libs.ethUtil.importPublic(pubkeyBuffer);
                    var addressBuffer = libs.ethUtil.publicToAddress(ethPubkey);
                    var hexAddress = addressBuffer.toString('hex');
                    // Use chainId based on selected network
                    // Ref: https://developers.rsk.co/rsk/architecture/account-based/#chainid
                    var chainId;
                    var rskNetworkName = networksName;
                    switch (rskNetworkName) {
                        case "R-BTC - RSK":
                            chainId = 30;
                            break;
                        case "tR-BTC - RSK Testnet":
                            chainId = 31;
                            break;
                        default:
                            chainId = null;
                    }
                    var checksumAddress = toChecksumAddressForRsk(hexAddress, chainId);
                    address = libs.ethUtil.addHexPrefix(checksumAddress);
                    pubkey = libs.ethUtil.addHexPrefix(pubkey);
                    if (hasPrivkey) {
                        privkey = libs.ethUtil.bufferToHex(keyPair.d.toBuffer());
                    }
                }

                // Handshake values are different
                if (networksName == "HNS - Handshake") {
                    var ring = libs.handshake.KeyRing.fromPublic(keyPair.getPublicKeyBuffer())
                    address = ring.getAddress().toString();
                }

                // Stellar is different
                if (networksName == "XLM - Stellar") {
                    //var purpose = parseIntNoNaN(DOM.bip44purpose.val(), 44);
                    var purpose = parseIntNoNaN(DOM_bip44purpose_val,44);
                    //var coin = parseIntNoNaN(DOM.bip44coin.val(), 0);
                    var coin = parseIntNoNaN(DOM_bip44coin_val, 0);
                    var path = "m/";
                    path += purpose + "'/";
                    path += coin + "'/" + index + "'";
                    var keypair = libs.stellarUtil.getKeypair(path, seed);
                    indexText = path;
                    privkey = keypair.secret();
                    pubkey = address = keypair.publicKey();
                }

                // Nano currency
                if (networksName == "NANO - Nano") {
                    var nanoKeypair = libs.nanoUtil.getKeypair(index, seed);
                    privkey = nanoKeypair.privKey;
                    pubkey = nanoKeypair.pubKey;
                    address = nanoKeypair.address;
                }

                if ((networksName == "NAS - Nebulas")) {
                    var privKeyBuffer = keyPair.d.toBuffer(32);
                    var nebulasAccount = libs.nebulas.Account.NewAccount();
                    nebulasAccount.setPrivateKey(privKeyBuffer);
                    address = nebulasAccount.getAddressString();
                    privkey = nebulasAccount.getPrivateKeyString();
                    pubkey = nebulasAccount.getPublicKeyString();
                }
                // Ripple values are different
                if (networksName == "XRP - Ripple") {
                    privkey = convertRipplePriv(privkey);
                    address = convertRippleAdrr(address);
                }
                // Jingtum values are different
                if (networksName == "SWTC - Jingtum") {
                    privkey = convertJingtumPriv(privkey);
                    address = convertJingtumAdrr(address);
                }
                // CasinoCoin values are different
                if (networksName == "CSC - CasinoCoin") {
                    privkey = convertCasinoCoinPriv(privkey);
                    address = convertCasinoCoinAdrr(address);
                }


                if ((networksName == "CRW - Crown")) {
                    address = libs.bitcoin.networks.crown.toNewAddress(address);
                }

                if (networksName == "EOS - EOSIO") {
                    address = ""
                    pubkey = EOSbufferToPublic(keyPair.getPublicKeyBuffer());
                    privkey = EOSbufferToPrivate(keyPair.d.toBuffer(32));
                }

                if (networksName == "FIO - Foundation for Interwallet Operability") {
                    address = ""
                    pubkey = FIObufferToPublic(keyPair.getPublicKeyBuffer());
                    privkey = FIObufferToPrivate(keyPair.d.toBuffer(32));
                }

                if (networksName == "ATOM - Cosmos Hub") {
                    const hrp = "cosmos";
                    address = CosmosBufferToAddress(keyPair.getPublicKeyBuffer(), hrp);
                    pubkey = CosmosBufferToPublic(keyPair.getPublicKeyBuffer(), hrp);
                    privkey = keyPair.d.toBuffer().toString("base64");
                }

                if (networksName == "RUNE - THORChain") {
                    const hrp = "thor";
                    address = CosmosBufferToAddress(keyPair.getPublicKeyBuffer(), hrp);
                    pubkey = keyPair.getPublicKeyBuffer().toString("hex");
                    privkey = keyPair.d.toBuffer().toString("hex");
                }

                if (networksName == "XWC - Whitecoin"){
                    address = XWCbufferToAddress(keyPair.getPublicKeyBuffer());
                    pubkey = XWCbufferToPublic(keyPair.getPublicKeyBuffer());
                    privkey = XWCbufferToPrivate(keyPair.d.toBuffer(32));
                }

                if (networksName == "LUNA - Terra") {
                    const hrp = "terra";
                    address = CosmosBufferToAddress(keyPair.getPublicKeyBuffer(), hrp);
                    pubkey = keyPair.getPublicKeyBuffer().toString("hex");
                    privkey = keyPair.d.toBuffer().toString("hex");
                }

                if (networksName == "IOV - Starname") {
                    const hrp = "star";
                    address = CosmosBufferToAddress(keyPair.getPublicKeyBuffer(), hrp);
                    pubkey = CosmosBufferToPublic(keyPair.getPublicKeyBuffer(), hrp);
                    privkey = keyPair.d.toBuffer().toString("base64");
                }





                //(indexText, address, pubkey, privkey);
                if (isLast) {
                    //hidePending();
                    //updateCsv();
                }
            }, 50)
        }

        init();

    }


    function clearDisplay() {
        clearAddressesList();
        clearKeys();
        //hideValidationError();
    }

    function clearAddressesList() {
        //DOM.addresses.empty();
        //DOM.csv.val("");
        stopGenerating();
    }

    function stopGenerating() {
        while (generationProcesses.length > 0) {
            var generation = generationProcesses.shift();
            generation.stop();
        }
    }

    function clearKeys() {
        clearRootKey();
        clearDerivedKeys();
    }

    function clearRootKey() {
        DOM_rootKey_val = ""; // DOM.rootKey.val("");
    }

    function clearDerivedKeys() {
        DOM_extendedPrivKey = ""; //DOM.extendedPrivKey.val("");
        DOM_extendedPubKey = ""; //DOM.extendedPubKey.val("");
        DOM_bip44accountXprv_val = "";//DOM.bip44accountXprv.val("");
        DOM_bip44accountXpub_val = "";//DOM.bip44accountXpub.val("");
    }



    function hasStrongRandom() {
        return 'crypto' in window && window['crypto'] !== null;
    }
    function delegateSelector(selector, event, handler) {

        var is = function(el, selector) {
            return (el.matches || el.matchesSelector || el.msMatchesSelector || el.mozMatchesSelector || el.webkitMatchesSelector || el.oMatchesSelector).call(el, selector);
        };

        var elements = document.querySelectorAll(selector);
        [].forEach.call(elements, function(el, i){
            el.addEventListener(event, function(e) {

                    handler(e);

            });
        });
    }
    function disableForms() {
        /*$("form").on("submit", function(e) {
            e.preventDefault();
        });*/

        delegateSelector('form', "submit", function(e) {
            e.preventDefault();
        });
    }

    function parseIntNoNaN(val, defaultVal) {
        var v = parseInt(val);
        if (isNaN(v)) {
            return defaultVal;
        }
        return v;
    }



    function findNearestWord(word) {
        var language = getLanguage();
        var words = WORDLISTS[language];
        var minDistance = 99;
        var closestWord = words[0];
        for (var i=0; i<words.length; i++) {
            var comparedTo = words[i];
            if (comparedTo.indexOf(word) == 0) {
                return comparedTo;
            }
            var distance = libs.levenshtein.get(word, comparedTo);
            if (distance < minDistance) {
                closestWord = comparedTo;
                minDistance = distance;
            }
        }
        return closestWord;
    }


    function getLanguage() {
        var defaultLanguage = "english";
        // Try to get from existing phrase
        var language = getLanguageFromPhrase();
        // Try to get from url if not from phrase
        if (language.length == 0) {
            language = getLanguageFromUrl();
        }
        // Default to English if no other option
        if (language.length == 0) {
            language = defaultLanguage;
        }
        return language;
    }

    function getLanguageFromPhrase(phrase) {
        // Check if how many words from existing phrase match a language.
        var language = "";
        if (!phrase) {
            phrase = DOM_phrase_val; //DOM.phrase.val();
        }
        if (phrase.length > 0) {
            var words = phraseToWordArray(phrase);
            var languageMatches = {};
            for (l in WORDLISTS) {
                // Track how many words match in this language
                languageMatches[l] = 0;
                for (var i=0; i<words.length; i++) {
                    var wordInLanguage = WORDLISTS[l].indexOf(words[i]) > -1;
                    if (wordInLanguage) {
                        languageMatches[l]++;
                    }
                }
                // Find languages with most word matches.
                // This is made difficult due to commonalities between Chinese
                // simplified vs traditional.
                var mostMatches = 0;
                var mostMatchedLanguages = [];
                for (var l in languageMatches) {
                    var numMatches = languageMatches[l];
                    if (numMatches > mostMatches) {
                        mostMatches = numMatches;
                        mostMatchedLanguages = [l];
                    }
                    else if (numMatches == mostMatches) {
                        mostMatchedLanguages.push(l);
                    }
                }
            }
            if (mostMatchedLanguages.length > 0) {
                // Use first language and warn if multiple detected
                language = mostMatchedLanguages[0];
                if (mostMatchedLanguages.length > 1) {
                    console.warn("Multiple possible languages");
                    console.warn(mostMatchedLanguages);
                }
            }
        }
        return language;
    }

    function getLanguageFromUrl() {
        for (var language in WORDLISTS) {
            if (window.location.hash.indexOf(language) > -1) {
                return language;
            }
        }
        return "";
    }

    function setMnemonicLanguage() {
        var language = getLanguage();
        // Load the bip39 mnemonic generator for this language if required
        if (!(language in mnemonics)) {
            mnemonics[language] = new Mnemonic(language);
        }
        mnemonic = mnemonics[language];
    }



    // TODO look at jsbip39 - mnemonic.splitWords
    function phraseToWordArray(phrase) {
        var words = phrase.split(/\s/g);
        var noBlanks = [];
        for (var i=0; i<words.length; i++) {
            var word = words[i];
            if (word.length > 0) {
                noBlanks.push(word);
            }
        }
        return noBlanks;
    }

    // TODO look at jsbip39 - mnemonic.joinWords
    function wordArrayToPhrase(words) {
        var phrase = words.join(" ");
        var language = getLanguageFromPhrase(phrase);
        if (language == "japanese") {
            phrase = words.join("\u3000");
        }
        return phrase;
    }



    function bip44TabSelected() {
        return  true;//DOM.bip44tab.hasClass("active");
    }




    function networkIsEthereum() {
        var name = networksName;
        return (name == "ETH - Ethereum")
            || (name == "ETC - Ethereum Classic")
            || (name == "EWT - EnergyWeb")
            || (name == "PIRL - Pirl")
            || (name == "MIX - MIX")
            || (name == "MOAC - MOAC")
            || (name == "MUSIC - Musicoin")
            || (name == "POA - Poa")
            || (name == "EXP - Expanse")
            || (name == "CLO - Callisto")
            || (name == "DXN - DEXON")
            || (name == "ELLA - Ellaism")
            || (name == "ESN - Ethersocial Network")
            || (name == "VET - VeChain")
            || (name == "ERE - EtherCore")
            || (name == "BSC - Binance Smart Chain")
    }

    function networkIsRsk() {
        var name = networksName;
        return (name == "R-BTC - RSK")
            || (name == "tR-BTC - RSK Testnet");
    }





    function setHdCoin(coinValue) {
        DOM_bip44coin_val = coinValue; //DOM.bip44coin.val(coinValue);

    }






    function uint8ArrayToHex(a) {
        var s = ""
        for (var i=0; i<a.length; i++) {
            var h = a[i].toString(16);
            while (h.length < 2) {
                h = "0" + h;
            }
            s = s + h;
        }
        return s;
    }



    // RSK - RSK functions - begin
    function stripHexPrefix(address) {
        if (typeof address !== "string") {
            throw new Error("address parameter should be a string.");
        }

        var hasPrefix = (address.substring(0, 2) === "0x" ||
            address.substring(0, 2) === "0X");

        return hasPrefix ? address.slice(2) : address;
    };

    function toChecksumAddressForRsk(address, chainId = null) {
        if (typeof address !== "string") {
            throw new Error("address parameter should be a string.");
        }

        if (!/^(0x)?[0-9a-f]{40}$/i.test(address)) {
            throw new Error("Given address is not a valid RSK address: " + address);
        }

        var stripAddress = stripHexPrefix(address).toLowerCase();
        var prefix = chainId != null ? chainId.toString() + "0x" : "";
        var keccakHash = libs.ethUtil.keccak256(prefix + stripAddress)
            .toString("hex")
            .replace(/^0x/i, "");
        var checksumAddress = "0x";

        for (var i = 0; i < stripAddress.length; i++) {
            checksumAddress +=
                parseInt(keccakHash[i], 16) >= 8 ?
                    stripAddress[i].toUpperCase() :
                    stripAddress[i];
        }

        return checksumAddress;
    }

    // RSK - RSK functions - end



    init();

})();
