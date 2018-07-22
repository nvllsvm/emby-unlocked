import events from './events.js';

const defaultTimeout = 20000;

const ConnectionMode = {
    Local: 0,
    Remote: 1,
    Manual: 2
};

function getServerAddress(server, mode) {

    switch (mode) {
        case ConnectionMode.Local:
            return server.LocalAddress;
        case ConnectionMode.Manual:
            return server.ManualAddress;
        case ConnectionMode.Remote:
            return server.RemoteAddress;
        default:
            return server.ManualAddress || server.LocalAddress || server.RemoteAddress;
    }
}

function paramsToString(params) {

    const values = [];

    for (const key in params) {

        const value = params[key];

        if (value !== null && value !== undefined && value !== '') {
            values.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
        }
    }
    return values.join('&');
}

function resolveFailure(instance, resolve) {

    resolve({
        State: 'Unavailable',
        ConnectUser: instance.connectUser()
    });
}

function mergeServers(credentialProvider, list1, list2) {

    for (let i = 0, length = list2.length; i < length; i++) {
        credentialProvider.addOrUpdateServer(list1, list2[i]);
    }

    return list1;
}

function updateServerInfo(server, systemInfo) {

    server.Name = systemInfo.ServerName;

    if (systemInfo.Id) {
        server.Id = systemInfo.Id;
    }
    if (systemInfo.LocalAddress) {
        server.LocalAddress = systemInfo.LocalAddress;
    }
    if (systemInfo.WanAddress) {
        server.RemoteAddress = systemInfo.WanAddress;
    }
}

function getEmbyServerUrl(baseUrl, handler) {
    return `${baseUrl}/emby/${handler}`;
}

function getFetchPromise(request) {

    const headers = request.headers || {};

    if (request.dataType === 'json') {
        headers.accept = 'application/json';
    }

    const fetchRequest = {
        headers,
        method: request.type,
        credentials: 'same-origin'
    };

    let contentType = request.contentType;

    if (request.data) {

        if (typeof request.data === 'string') {
            fetchRequest.body = request.data;
        } else {
            fetchRequest.body = paramsToString(request.data);

            contentType = contentType || 'application/x-www-form-urlencoded; charset=UTF-8';
        }
    }

    if (contentType) {

        headers['Content-Type'] = contentType;
    }

    if (!request.timeout) {
        return fetch(request.url, fetchRequest);
    }

    return fetchWithTimeout(request.url, fetchRequest, request.timeout);
}

function fetchWithTimeout(url, options, timeoutMs) {

    console.log(`fetchWithTimeout: timeoutMs: ${timeoutMs}, url: ${url}`);

    return new Promise((resolve, reject) => {

        const timeout = setTimeout(reject, timeoutMs);

        options = options || {};
        options.credentials = 'same-origin';

        fetch(url, options).then(response => {
            clearTimeout(timeout);

            console.log(`fetchWithTimeout: succeeded connecting to url: ${url}`);

            resolve(response);
        }, error => {

            clearTimeout(timeout);

            console.log(`fetchWithTimeout: timed out connecting to url: ${url}`);

            reject();
        });
    });
}

function ajax(request) {

    if (!request) {
        throw new Error("Request cannot be null");
    }

    request.headers = request.headers || {};

    console.log(`ConnectionManager requesting url: ${request.url}`);

    return getFetchPromise(request).then(response => {

        console.log(`ConnectionManager response status: ${response.status}, url: ${request.url}`);

        if (response.status < 400) {

            if (request.dataType === 'json' || request.headers.accept === 'application/json') {
                return response.json();
            } else {
                return response;
            }
        } else {
            return Promise.reject(response);
        }

    }, err => {

        console.log(`ConnectionManager request failed to url: ${request.url}`);
        throw err;
    });
}

function getConnectUrl(handler) {
    return `https://connect.emby.media/service/${handler}`;
}

function replaceAll(originalString, strReplace, strWith) {
    const reg = new RegExp(strReplace, 'ig');
    return originalString.replace(reg, strWith);
}

function normalizeAddress(address) {

    // attempt to correct bad input
    address = address.trim();

    if (address.toLowerCase().indexOf('http') !== 0) {
        address = `http://${address}`;
    }

    // Seeing failures in iOS when protocol isn't lowercase
    address = replaceAll(address, 'Http:', 'http:');
    address = replaceAll(address, 'Https:', 'https:');

    return address;
}

function stringEqualsIgnoreCase(str1, str2) {

    return (str1 || '').toLowerCase() === (str2 || '').toLowerCase();
}

function compareVersions(a, b) {

    // -1 a is smaller
    // 1 a is larger
    // 0 equal
    a = a.split('.');
    b = b.split('.');

    for (let i = 0, length = Math.max(a.length, b.length); i < length; i++) {
        const aVal = parseInt(a[i] || '0');
        const bVal = parseInt(b[i] || '0');

        if (aVal < bVal) {
            return -1;
        }

        if (aVal > bVal) {
            return 1;
        }
    }

    return 0;
}

export default class ConnectionManager {
    constructor(
        credentialProvider,
        appStorage,
        apiClientFactory,
        serverDiscoveryFn,
        wakeOnLanFn,
        appName,
        appVersion,
        deviceName,
        deviceId,
        capabilities,
        devicePixelRatio) {

        console.log('Begin ConnectionManager constructor');

        const self = this;
        this._apiClients = [];

        let connectUser;
        self.connectUser = () => connectUser;

        self._minServerVersion = '3.2.33';

        self.appVersion = () => appVersion;

        self.appName = () => appName;

        self.capabilities = () => capabilities;

        self.deviceId = () => deviceId;

        self.credentialProvider = () => credentialProvider;

        self.connectUserId = () => credentialProvider.credentials().ConnectUserId;

        self.connectToken = () => credentialProvider.credentials().ConnectAccessToken;

        self.getServerInfo = id => {

            const servers = credentialProvider.credentials().Servers;

            return servers.filter(s => s.Id === id)[0];
        };

        self.getLastUsedServer = () => {

            const servers = credentialProvider.credentials().Servers;

            servers.sort((a, b) => (b.DateLastAccessed || 0) - (a.DateLastAccessed || 0));

            if (!servers.length) {
                return null;
            }

            return servers[0];
        };

        self.addApiClient = apiClient => {

            self._apiClients.push(apiClient);

            const existingServers = credentialProvider.credentials().Servers.filter(s => stringEqualsIgnoreCase(s.ManualAddress, apiClient.serverAddress()) ||
                stringEqualsIgnoreCase(s.LocalAddress, apiClient.serverAddress()) ||
                stringEqualsIgnoreCase(s.RemoteAddress, apiClient.serverAddress()));

            const existingServer = existingServers.length ? existingServers[0] : apiClient.serverInfo();
            existingServer.DateLastAccessed = new Date().getTime();
            existingServer.LastConnectionMode = ConnectionMode.Manual;
            existingServer.ManualAddress = apiClient.serverAddress();

            if (apiClient.manualAddressOnly) {
                existingServer.manualAddressOnly = true;
            }

            apiClient.serverInfo(existingServer);

            apiClient.onAuthenticated = (instance, result) => onAuthenticated(instance, result, {}, true);

            if (!existingServers.length) {
                const credentials = credentialProvider.credentials();
                credentials.Servers = [existingServer];
                credentialProvider.credentials(credentials);
            }

            events.trigger(self, 'apiclientcreated', [apiClient]);
        };

        self.clearData = () => {

            console.log('connection manager clearing data');

            connectUser = null;
            const credentials = credentialProvider.credentials();
            credentials.ConnectAccessToken = null;
            credentials.ConnectUserId = null;
            credentials.Servers = [];
            credentialProvider.credentials(credentials);
        };

        function onConnectUserSignIn(user) {

            connectUser = user;
            events.trigger(self, 'connectusersignedin', [user]);
        }

        self._getOrAddApiClient = (server, serverUrl) => {

            let apiClient = self.getApiClient(server.Id);

            if (!apiClient) {

                apiClient = new apiClientFactory(serverUrl, appName, appVersion, deviceName, deviceId, devicePixelRatio);

                self._apiClients.push(apiClient);

                apiClient.serverInfo(server);

                apiClient.onAuthenticated = (instance, result) => {
                    return onAuthenticated(instance, result, {}, true);
                };

                events.trigger(self, 'apiclientcreated', [apiClient]);
            }

            console.log('returning instance from getOrAddApiClient');
            return apiClient;
        };

        self.getOrCreateApiClient = serverId => {

            const credentials = credentialProvider.credentials();
            const servers = credentials.Servers.filter(s => stringEqualsIgnoreCase(s.Id, serverId));

            if (!servers.length) {
                throw new Error(`Server not found: ${serverId}`);
            }

            const server = servers[0];

            return self._getOrAddApiClient(server, getServerAddress(server, server.LastConnectionMode));
        };

        function onAuthenticated(apiClient, result, options, saveCredentials) {

            const credentials = credentialProvider.credentials();
            const servers = credentials.Servers.filter(s => s.Id === result.ServerId);

            const server = servers.length ? servers[0] : apiClient.serverInfo();

            if (options.updateDateLastAccessed !== false) {
                server.DateLastAccessed = new Date().getTime();
            }
            server.Id = result.ServerId;

            if (saveCredentials) {
                server.UserId = result.User.Id;
                server.AccessToken = result.AccessToken;
            } else {
                server.UserId = null;
                server.AccessToken = null;
            }

            credentialProvider.addOrUpdateServer(credentials.Servers, server);
            credentialProvider.credentials(credentials);

            // set this now before updating server info, otherwise it won't be set in time
            apiClient.enableAutomaticBitrateDetection = options.enableAutomaticBitrateDetection;

            apiClient.serverInfo(server);
            afterConnected(apiClient, options);

            return onLocalUserSignIn(server, apiClient.serverAddress(), result.User);
        }

        function afterConnected(apiClient, options = {}) {
            if (options.reportCapabilities !== false) {
                apiClient.reportCapabilities(capabilities);
            }
            apiClient.enableAutomaticBitrateDetection = options.enableAutomaticBitrateDetection;

            if (options.enableWebSocket !== false) {
                console.log('calling apiClient.ensureWebSocket');

                apiClient.ensureWebSocket();
            }
        }

        function onLocalUserSignIn(server, serverUrl, user) {

            // Ensure this is created so that listeners of the event can get the apiClient instance
            self._getOrAddApiClient(server, serverUrl);

            // This allows the app to have a single hook that fires before any other
            const promise = self.onLocalUserSignedIn ? self.onLocalUserSignedIn.call(self, user) : Promise.resolve();

            return promise.then(() => {
                events.trigger(self, 'localusersignedin', [user]);
            });
        }

        function ensureConnectUser(credentials) {

            if (connectUser && connectUser.Id === credentials.ConnectUserId) {
                return Promise.resolve();
            }

            else if (credentials.ConnectUserId && credentials.ConnectAccessToken) {

                connectUser = null;

                return getConnectUser(credentials.ConnectUserId, credentials.ConnectAccessToken).then(user => {

                    onConnectUserSignIn(user);
                    return Promise.resolve();

                }, () => Promise.resolve());

            } else {
                return Promise.resolve();
            }
        }

        function getConnectUser(userId, accessToken) {

            if (!userId) {
                throw new Error("null userId");
            }
            if (!accessToken) {
                throw new Error("null accessToken");
            }

            const url = `https://connect.emby.media/service/user?id=${userId}`;

            return ajax({
                type: "GET",
                url,
                dataType: "json",
                headers: {
                    "X-Application": `${appName}/${appVersion}`,
                    "X-Connect-UserToken": accessToken
                }

            });
        }

        function addAuthenticationInfoFromConnect(server, serverUrl, credentials) {

            if (!server.ExchangeToken) {
                throw new Error("server.ExchangeToken cannot be null");
            }
            if (!credentials.ConnectUserId) {
                throw new Error("credentials.ConnectUserId cannot be null");
            }

            const = getEmbyServerUrl(serverUrl, `Connect/Exchange?format=json&ConnectUserId=${credentials.ConnectUserId}`);

            const auth = `MediaBrowser Client="${appName}", Device="${deviceName}", DeviceId="${deviceId}", Version="${appVersion}"`;

            return ajax({
                type: "GET",
                url,
                dataType: "json",
                headers: {
                    "X-MediaBrowser-Token": server.ExchangeToken,
                    "X-Emby-Authorization": auth
                }

            }).then(auth => {

                server.UserId = auth.LocalUserId;
                server.AccessToken = auth.AccessToken;
                return auth;

            }, () => {

                server.UserId = null;
                server.AccessToken = null;
                return Promise.reject();

            });
        }

        function validateAuthentication(server, serverUrl) {

            return ajax({

                type: "GET",
                url: getEmbyServerUrl(serverUrl, "System/Info"),
                dataType: "json",
                headers: {
                    "X-MediaBrowser-Token": server.AccessToken
                }

            }).then(systemInfo => {

                updateServerInfo(server, systemInfo);
                return Promise.resolve();

            }, () => {

                server.UserId = null;
                server.AccessToken = null;
                return Promise.resolve();
            });
        }

        function getImageUrl(localUser) {

            if (connectUser && connectUser.ImageUrl) {
                return {
                    url: connectUser.ImageUrl
                };
            }
            if (localUser && localUser.PrimaryImageTag) {

                const apiClient = self.getApiClient(localUser);

                const url = apiClient.getUserImageUrl(localUser.Id, {
                    tag: localUser.PrimaryImageTag,
                    type: "Primary"
                });

                return {
                    url,
                    supportsParams: true
                };
            }

            return {
                url: null,
                supportsParams: false
            };
        }

        self.user = apiClient => new Promise((resolve, reject) => {

            let localUser;

            function onLocalUserDone(e) {

                const image = getImageUrl(localUser);

                resolve({
                    localUser,
                    name: connectUser ? connectUser.Name : (localUser ? localUser.Name : null),
                    imageUrl: image.url,
                    supportsImageParams: image.supportsParams,
                    connectUser
                });
            }

            function onEnsureConnectUserDone() {

                if (apiClient && apiClient.getCurrentUserId()) {
                    apiClient.getCurrentUser().then(u => {
                        localUser = u;
                        onLocalUserDone();

                    }, onLocalUserDone);
                } else {
                    onLocalUserDone();
                }
            }

            const credentials = credentialProvider.credentials();

            if (credentials.ConnectUserId && credentials.ConnectAccessToken && !(apiClient && apiClient.getCurrentUserId())) {
                ensureConnectUser(credentials).then(onEnsureConnectUserDone, onEnsureConnectUserDone);
            } else {
                onEnsureConnectUserDone();
            }
        });

        self.logout = () => {

            console.log('begin connectionManager loguot');
            const promises = [];

            for (let i = 0, length = self._apiClients.length; i < length; i++) {

                const apiClient = self._apiClients[i];

                if (apiClient.accessToken()) {
                    promises.push(logoutOfServer(apiClient));
                }
            }

            return Promise.all(promises).then(() => {

                const credentials = credentialProvider.credentials();

                const servers = credentials.Servers.filter(u => u.UserLinkType !== "Guest");

                for (let j = 0, numServers = servers.length; j < numServers; j++) {

                    const server = servers[j];

                    server.UserId = null;
                    server.AccessToken = null;
                    server.ExchangeToken = null;
                }

                credentials.Servers = servers;
                credentials.ConnectAccessToken = null;
                credentials.ConnectUserId = null;

                credentialProvider.credentials(credentials);

                if (connectUser) {
                    connectUser = null;
                    events.trigger(self, 'connectusersignedout');
                }
            });
        };

        function logoutOfServer(apiClient) {

            const serverInfo = apiClient.serverInfo() || {};

            const logoutInfo = {
                serverId: serverInfo.Id
            };

            return apiClient.logout().then(() => {

                events.trigger(self, 'localusersignedout', [logoutInfo]);
            }, () => {

                events.trigger(self, 'localusersignedout', [logoutInfo]);
            });
        }

        function getConnectServers(credentials) {

            console.log('Begin getConnectServers');

            if (!credentials.ConnectAccessToken || !credentials.ConnectUserId) {
                return Promise.resolve([]);
            }

            const url = `https://connect.emby.media/service/servers?userId=${credentials.ConnectUserId}`;

            return ajax({
                type: "GET",
                url,
                dataType: "json",
                headers: {
                    "X-Application": `${appName}/${appVersion}`,
                    "X-Connect-UserToken": credentials.ConnectAccessToken
                }

            }).then(servers => servers.map(i => ({
                ExchangeToken: i.AccessKey,
                ConnectServerId: i.Id,
                Id: i.SystemId,
                Name: i.Name,
                RemoteAddress: i.Url,
                LocalAddress: i.LocalAddress,
                UserLinkType: (i.UserType || '').toLowerCase() === "guest" ? "Guest" : "LinkedUser"
            })), () => credentials.Servers.slice(0).filter(s => s.ExchangeToken));
        }

        self.getSavedServers = () => {

            const credentials = credentialProvider.credentials();

            const servers = credentials.Servers.slice(0);

            servers.sort((a, b) => (b.DateLastAccessed || 0) - (a.DateLastAccessed || 0));

            return servers;
        };

        self.getAvailableServers = () => {

            console.log('Begin getAvailableServers');

            // Clone the array
            const credentials = credentialProvider.credentials();

            return Promise.all([getConnectServers(credentials), findServers()]).then(responses => {

                const connectServers = responses[0];
                const foundServers = responses[1];

                let servers = credentials.Servers.slice(0);
                mergeServers(credentialProvider, servers, foundServers);
                mergeServers(credentialProvider, servers, connectServers);

                servers = filterServers(servers, connectServers);

                servers.sort((a, b) => (b.DateLastAccessed || 0) - (a.DateLastAccessed || 0));

                credentials.Servers = servers;

                credentialProvider.credentials(credentials);

                return servers;
            });
        };

        function filterServers(servers, connectServers) {

            return servers.filter(server => {

                // It's not a connect server, so assume it's still valid
                if (!server.ExchangeToken) {
                    return true;
                }

                return connectServers.filter(connectServer => server.Id === connectServer.Id).length > 0;
            });
        }

        function findServers() {

            return new Promise((resolve, reject) => {

                const onFinish = foundServers => {
                    const servers = foundServers.map(foundServer => {

                        const info = {
                            Id: foundServer.Id,
                            LocalAddress: convertEndpointAddressToManualAddress(foundServer) || foundServer.Address,
                            Name: foundServer.Name
                        };

                        info.LastConnectionMode = info.ManualAddress ? ConnectionMode.Manual : ConnectionMode.Local;

                        return info;
                    });
                    resolve(servers);
                };

                serverDiscoveryFn().then(serverDiscovery => {
                    serverDiscovery.default.findServers(1000).then(onFinish, () => {
                        onFinish([]);
                    });

                });
            });
        }

        function convertEndpointAddressToManualAddress(info) {

            if (info.Address && info.EndpointAddress) {
                let address = info.EndpointAddress.split(":")[0];

                // Determine the port, if any
                const parts = info.Address.split(":");
                if (parts.length > 1) {
                    const portString = parts[parts.length - 1];

                    if (!isNaN(parseInt(portString))) {
                        address += `:${portString}`;
                    }
                }

                return normalizeAddress(address);
            }

            return null;
        }

        self.connectToServers = (servers, options) => {

            console.log(`Begin connectToServers, with ${servers.length} servers`);

            const firstServer = servers.length ? servers[0] : null;
            // See if we have any saved credentials and can auto sign in
            if (firstServer) {
                return self.connectToServer(firstServer, options).then((result) => {

                    if (result.State === 'Unavailable') {

                        result.State = 'ServerSelection';
                    }

                    console.log('resolving connectToServers with result.State: ' + result.State);
                    return result;
                });
            }

            return Promise.resolve({
                Servers: servers,
                State: (!servers.length && !self.connectUser()) ? 'ConnectSignIn' : 'ServerSelection',
                ConnectUser: self.connectUser()
            });
        };

        function getTryConnectPromise(url, connectionMode, state, resolve, reject) {

            console.log('getTryConnectPromise ' + url);

            ajax({

                url: getEmbyServerUrl(url, 'system/info/public'),
                timeout: defaultTimeout,
                type: 'GET',
                dataType: 'json'

            }).then((result) => {

                if (!state.resolved) {
                    state.resolved = true;

                    console.log("Reconnect succeeded to " + url);
                    resolve({
                        url: url,
                        connectionMode: connectionMode,
                        data: result
                    });
                }

            }, () => {

                console.log("Reconnect failed to " + url);

                if (!state.resolved) {
                    state.rejects++;
                    if (state.rejects >= state.numAddresses) {
                        reject();
                    }
                }
            });
        }

        function tryReconnect(serverInfo) {

            const addresses = [];
            const addressesStrings = [];

            // the timeouts are a small hack to try and ensure the remote address doesn't resolve first

            // manualAddressOnly is used for the local web app that always connects to a fixed address
            if (!serverInfo.manualAddressOnly && serverInfo.LocalAddress && addressesStrings.indexOf(serverInfo.LocalAddress) === -1) {
                addresses.push({ url: serverInfo.LocalAddress, mode: ConnectionMode.Local, timeout: 0 });
                addressesStrings.push(addresses[addresses.length - 1].url);
            }
            if (serverInfo.ManualAddress && addressesStrings.indexOf(serverInfo.ManualAddress) === -1) {
                addresses.push({ url: serverInfo.ManualAddress, mode: ConnectionMode.Manual, timeout: 100 });
                addressesStrings.push(addresses[addresses.length - 1].url);
            }
            if (!serverInfo.manualAddressOnly && serverInfo.RemoteAddress && addressesStrings.indexOf(serverInfo.RemoteAddress) === -1) {
                addresses.push({ url: serverInfo.RemoteAddress, mode: ConnectionMode.Remote, timeout: 200 });
                addressesStrings.push(addresses[addresses.length - 1].url);
            }

            console.log('tryReconnect: ' + addressesStrings.join('|'));

            return new Promise((resolve, reject) => {

                const state = {};
                state.numAddresses = addresses.length;
                state.rejects = 0;

                addresses.map((url) => {

                    setTimeout(() => {
                        if (!state.resolved) {
                            getTryConnectPromise(url.url, url.mode, state, resolve, reject);
                        }

                    }, url.timeout);
                });
            });
        }

        self.connectToServer = (server, options) => {

            console.log('begin connectToServer');

            return new Promise((resolve, reject) => {

                options = options || {};

                tryReconnect(server).then((result) => {

                    const serverUrl = result.url;
                    const connectionMode = result.connectionMode;
                    result = result.data;

                    if (compareVersions(self.minServerVersion(), result.Version) === 1) {

                        console.log('minServerVersion requirement not met. Server version: ' + result.Version);
                        resolve({
                            State: 'ServerUpdateNeeded',
                            Servers: [server]
                        });

                    }
                    else if (server.Id && result.Id !== server.Id) {

                        console.log('http request succeeded, but found a different server Id than what was expected');
                        resolveFailure(self, resolve);

                    }
                    else {
                        onSuccessfulConnection(server, result, connectionMode, serverUrl, options, resolve);
                    }

                }, () => {

                    resolveFailure(self, resolve);
                });
            });
        };

        function onSuccessfulConnection(server, systemInfo, connectionMode, serverUrl, options, resolve) {

            const credentials = credentialProvider.credentials();
            options = options || {};
            if (credentials.ConnectAccessToken && options.enableAutoLogin !== false) {

                ensureConnectUser(credentials).then(() => {

                    if (server.ExchangeToken) {
                        addAuthenticationInfoFromConnect(server, serverUrl, credentials).then(() => {

                            afterConnectValidated(server, credentials, systemInfo, connectionMode, serverUrl, true, options, resolve);

                        }, () => {

                            afterConnectValidated(server, credentials, systemInfo, connectionMode, serverUrl, true, options, resolve);
                        });

                    } else {

                        afterConnectValidated(server, credentials, systemInfo, connectionMode, serverUrl, true, options, resolve);
                    }
                });
            }
            else {
                afterConnectValidated(server, credentials, systemInfo, connectionMode, serverUrl, true, options, resolve);
            }
        }

        function afterConnectValidated(
            server,
            credentials,
            systemInfo,
            connectionMode,
            serverUrl,
            verifyLocalAuthentication,
            options = {},
            resolve) {
            if (options.enableAutoLogin === false) {

                server.UserId = null;
                server.AccessToken = null;

            } else if (verifyLocalAuthentication && server.AccessToken && options.enableAutoLogin !== false) {

                validateAuthentication(server, serverUrl).then(() => {

                    afterConnectValidated(server, credentials, systemInfo, connectionMode, serverUrl, false, options, resolve);
                });

                return;
            }

            updateServerInfo(server, systemInfo);

            server.LastConnectionMode = connectionMode;

            if (options.updateDateLastAccessed !== false) {
                server.DateLastAccessed = new Date().getTime();
            }
            credentialProvider.addOrUpdateServer(credentials.Servers, server);
            credentialProvider.credentials(credentials);

            const result = {
                Servers: []
            };

            result.ApiClient = self._getOrAddApiClient(server, serverUrl);

            result.ApiClient.setSystemInfo(systemInfo);

            result.State = server.AccessToken && options.enableAutoLogin !== false ?
                'SignedIn' :
                'ServerSignIn';

            result.Servers.push(server);

            // set this now before updating server info, otherwise it won't be set in time
            result.ApiClient.enableAutomaticBitrateDetection = options.enableAutomaticBitrateDetection;

            result.ApiClient.updateServerInfo(server, serverUrl);

            const resolveActions = function () {
                resolve(result);

                events.trigger(self, 'connected', [result]);
            };

            if (result.State === 'SignedIn') {
                afterConnected(result.ApiClient, options);

                result.ApiClient.getCurrentUser().then((user) => {
                    onLocalUserSignIn(server, serverUrl, user).then(resolveActions, resolveActions);
                }, resolveActions);
            }
            else {
                resolveActions();
            }
        }

        self.connectToAddress = function (address, options) {

            if (!address) {
                return Promise.reject();
            }

            address = normalizeAddress(address);
            const instance = this;

            function onFail() {
                console.log(`connectToAddress ${address} failed`);
                return Promise.resolve({
                    State: 'Unavailable',
                    ConnectUser: instance.connectUser()
                });
            }

            const server = {
                ManualAddress: address,
                LastConnectionMode: ConnectionMode.Manual
            };

            return self.connectToServer(server, options).catch(onFail);
        };

        self.loginToConnect = (username, password) => {

            if (!username) {
                return Promise.reject();
            }
            if (!password) {
                return Promise.reject();
            }

            return ajax({
                type: "POST",
                url: "https://connect.emby.media/service/user/authenticate",
                data: {
                    nameOrEmail: username,
                    rawpw: password
                },
                dataType: "json",
                contentType: 'application/x-www-form-urlencoded; charset=UTF-8',
                headers: {
                    "X-Application": `${appName}/${appVersion}`
                }

            }).then(result => {

                const credentials = credentialProvider.credentials();

                credentials.ConnectAccessToken = result.AccessToken;
                credentials.ConnectUserId = result.User.Id;

                credentialProvider.credentials(credentials);

                onConnectUserSignIn(result.User);

                return result;
            });
        };

        self.signupForConnect = options => {

            const email = options.email;
            const username = options.username;
            const password = options.password;
            const passwordConfirm = options.passwordConfirm;

            if (!email) {
                return Promise.reject({ errorCode: 'invalidinput' });
            }
            if (!username) {
                return Promise.reject({ errorCode: 'invalidinput' });
            }
            if (!password) {
                return Promise.reject({ errorCode: 'invalidinput' });
            }
            if (!passwordConfirm) {
                return Promise.reject({ errorCode: 'passwordmatch' });
            }
            if (password !== passwordConfirm) {
                return Promise.reject({ errorCode: 'passwordmatch' });
            }

            const data = {
                email,
                userName: username,
                rawpw: password
            };

            if (options.grecaptcha) {
                data.grecaptcha = options.grecaptcha;
            }

            return ajax({
                type: "POST",
                url: "https://connect.emby.media/service/register",
                data,
                dataType: "json",
                contentType: 'application/x-www-form-urlencoded; charset=UTF-8',
                headers: {
                    "X-Application": `${appName}/${appVersion}`,
                    "X-CONNECT-TOKEN": "CONNECT-REGISTER"
                }

            }).catch(response => {

                try {
                    return response.json();
                } catch (err) {
                    throw err;
                }

            }).then(result => {
                if (result && result.Status) {

                    if (result.Status === 'SUCCESS') {
                        return Promise.resolve(result);
                    }
                    return Promise.reject({ errorCode: result.Status });
                } else {
                    Promise.reject();
                }
            });
        };

        self.getUserInvitations = () => {

            const connectToken = self.connectToken();

            if (!connectToken) {
                throw new Error("null connectToken");
            }
            if (!self.connectUserId()) {
                throw new Error("null connectUserId");
            }

            const url = `https://connect.emby.media/service/servers?userId=${self.connectUserId()}&status=Waiting`;

            return ajax({
                type: "GET",
                url,
                dataType: "json",
                headers: {
                    "X-Connect-UserToken": connectToken,
                    "X-Application": `${appName}/${appVersion}`
                }

            });
        };

        self.deleteServer = serverId => {

            if (!serverId) {
                throw new Error("null serverId");
            }

            let server = credentialProvider.credentials().Servers.filter(s => s.Id === serverId);
            server = server.length ? server[0] : null;

            return new Promise((resolve, reject) => {

                function onDone() {
                    const credentials = credentialProvider.credentials();

                    credentials.Servers = credentials.Servers.filter(s => s.Id !== serverId);

                    credentialProvider.credentials(credentials);
                    resolve();
                }

                if (!server.ConnectServerId) {
                    onDone();
                    return;
                }

                const connectToken = self.connectToken();
                const connectUserId = self.connectUserId();

                if (!connectToken || !connectUserId) {
                    onDone();
                    return;
                }

                const url = `https://connect.emby.media/service/serverAuthorizations?serverId=${server.ConnectServerId}&userId=${connectUserId}`;

                ajax({
                    type: "DELETE",
                    url,
                    headers: {
                        "X-Connect-UserToken": connectToken,
                        "X-Application": `${appName}/${appVersion}`
                    }

                }).then(onDone, onDone);
            });
        };

        self.rejectServer = serverId => {

            const connectToken = self.connectToken();

            if (!serverId) {
                throw new Error("null serverId");
            }
            if (!connectToken) {
                throw new Error("null connectToken");
            }
            if (!self.connectUserId()) {
                throw new Error("null connectUserId");
            }

            const url = `https://connect.emby.media/service/serverAuthorizations?serverId=${serverId}&userId=${self.connectUserId()}`;

            return fetch(url, {
                method: "DELETE",
                headers: {
                    "X-Connect-UserToken": connectToken,
                    "X-Application": `${appName}/${appVersion}`
                }
            });
        };

        self.acceptServer = serverId => {

            const connectToken = self.connectToken();

            if (!serverId) {
                throw new Error("null serverId");
            }
            if (!connectToken) {
                throw new Error("null connectToken");
            }
            if (!self.connectUserId()) {
                throw new Error("null connectUserId");
            }

            const url = `https://connect.emby.media/service/ServerAuthorizations/accept?serverId=${serverId}&userId=${self.connectUserId()}`;

            return ajax({
                type: "GET",
                url,
                headers: {
                    "X-Connect-UserToken": connectToken,
                    "X-Application": `${appName}/${appVersion}`
                }

            });
        };

        function getCacheKey(feature, apiClient, options = {}) {
            const viewOnly = options.viewOnly;

            let cacheKey = `regInfo-${apiClient.serverId()}`;

            if (viewOnly) {
                cacheKey += '-viewonly';
            }

            return cacheKey;
        }

        self.resetRegistrationInfo = apiClient => {

            let cacheKey = getCacheKey('themes', apiClient, { viewOnly: true });
            appStorage.removeItem(cacheKey);

            cacheKey = getCacheKey('themes', apiClient, { viewOnly: false });
            appStorage.removeItem(cacheKey);
        };

        self.getRegistrationInfo = (feature, apiClient, options) => {
            var cacheKey = getCacheKey(feature, apiClient, options);
            appStorage.setItem(cacheKey, JSON.stringify({
                lastValidDate: new Date().getTime(),
                deviceId: self.deviceId()
            }));
            return Promise.resolve();
        };

        function addAppInfoToConnectRequest(request) {
            request.headers = request.headers || {};
            request.headers['X-Application'] = `${appName}/${appVersion}`;
        }

        self.createPin = () => {

            const request = {
                type: 'POST',
                url: getConnectUrl('pin'),
                data: {
                    deviceId
                },
                dataType: 'json'
            };

            addAppInfoToConnectRequest(request);

            return ajax(request);
        };

        self.getPinStatus = pinInfo => {

            if (!pinInfo) {
                throw new Error('pinInfo cannot be null');
            }

            const queryString = {
                deviceId: pinInfo.DeviceId,
                pin: pinInfo.Pin
            };

            const request = {
                type: 'GET',
                url: `${getConnectUrl('pin')}?${paramsToString(queryString)}`,
                dataType: 'json'
            };

            addAppInfoToConnectRequest(request);

            return ajax(request);

        };

        function exchangePin(pinInfo) {

            if (!pinInfo) {
                throw new Error('pinInfo cannot be null');
            }

            const request = {
                type: 'POST',
                url: getConnectUrl('pin/authenticate'),
                data: {
                    deviceId: pinInfo.DeviceId,
                    pin: pinInfo.Pin
                },
                dataType: 'json'
            };

            addAppInfoToConnectRequest(request);

            return ajax(request);
        }

        self.exchangePin = pinInfo => {

            if (!pinInfo) {
                throw new Error('pinInfo cannot be null');
            }

            return exchangePin(pinInfo).then(result => {

                const credentials = credentialProvider.credentials();
                credentials.ConnectAccessToken = result.AccessToken;
                credentials.ConnectUserId = result.UserId;
                credentialProvider.credentials(credentials);

                return ensureConnectUser(credentials);
            });
        };
    }

    connect(options) {

        console.log('Begin connect');

        const instance = this;

        return instance.getAvailableServers().then(servers => instance.connectToServers(servers, options));
    }

    handleMessageReceived(msg) {

        const serverId = msg.ServerId;
        if (serverId) {
            const apiClient = this.getApiClient(serverId);
            if (apiClient) {

                if (typeof (msg.Data) === 'string') {
                    try {
                        msg.Data = JSON.parse(msg.Data);
                    }
                    catch (err) {
                    }
                }

                apiClient.handleMessageReceived(msg);
            }
        }
    }

    isLoggedIntoConnect() {

        // Make sure it returns true or false
        if (!this.connectToken() || !this.connectUserId()) {
            return false;
        }
        return true;
    }

    getApiClients() {

        const servers = this.getSavedServers();

        for (let i = 0, length = servers.length; i < length; i++) {
            const server = servers[i];
            if (server.Id) {
                this._getOrAddApiClient(server, getServerAddress(server, server.LastConnectionMode));
            }
        }

        return this._apiClients;
    }

    getApiClient(item) {

        if (!item) {
            throw new Error('item or serverId cannot be null');
        }

        // Accept string + object
        if (item.ServerId) {
            item = item.ServerId;
        }

        return this._apiClients.filter(a => {

            const serverInfo = a.serverInfo();

            // We have to keep this hack in here because of the addApiClient method
            return !serverInfo || serverInfo.Id === item;

        })[0];
    }

    minServerVersion(val) {

        if (val) {
            this._minServerVersion = val;
        }

        return this._minServerVersion;
    }
}
