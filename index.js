(function (module) {
    "use strict";
    /* globals app, socket */
    var user = require.main.require('./src/user'),
        groups = require.main.require('./src/groups'),
        meta = require.main.require('./src/meta'),
        db = require.main.require('./src/database'),
        passport = require.main.require('passport'),
        async = require.main.require('async'),
        local_strategy = require.main.require('passport-local').Strategy,
        winston = require.main.require('winston'),
        ldapjs = require('ldapjs');
    const controllers = require.main.require('./src/controllers');


    var master_config = {};
    var nodebb_ldap = {
        whitelistFields: (params, callback) => {
            params.whitelist.push('nodebbldap:data');
            callback(null, params);
        },
        adminHeader: (custom_header, callback) => {
            custom_header.plugins.push({
                "route": "/plugins/nodebb_ldap",
                "icon": "fa-cog",
                "name": "LDAP Settings"
            });
            callback(null, custom_header);
        },
        getConfig: (options, callback) => {
            options = options ? options : {};
            meta.settings.get('nodebbldap', (err, settings) => {
                if (err) {
                    return callback(err, options);
                }
                options.nodebbldap = settings;
                callback(null, options);
            });
        },

        init: (params, callback) => {
            const render = (req, res, next) => {
                res.render('nodebb_ldap', {});
            };
            winston.verbose("[LDAP] Calling Init")
            params.router.get('/admin/plugins/nodebb_ldap', params.middleware.admin.buildHeader, render);
            params.router.get('/api/admin/plugins/nodebb_ldap', render);

            async.waterfall([
                nodebb_ldap.updateConfig,
                nodebb_ldap.findLdapGroups,
                (groups, callback) => {
                    async.each(groups, nodebb_ldap.createGroup, callback);
                }
            ], (e) => {
                if (e) {
                    console.error('config seems invalid', e);
                }
                callback();
            });
        },

        updateConfig: (callback) => {
            winston.verbose("[LDAP] Calling updateConfig")
            nodebb_ldap.getConfig(null, (err, config) => {
                if (err) {
                    return callback(err);
                }
                master_config = config.nodebbldap;
                //winston.verbose("[LDAP] master_config " + JSON.stringify(master_config))
                callback();
            });
        },

        override: () => {
            winston.verbose("[LDAP] Calling override")
            const local = new local_strategy({passReqToCallback: true}, controllers.authentication.localLogin)
            nodebb_ldap.updateConfig(() => {
                if (!master_config.server) {
                    passport.use(local);
                } else {
                    try {
                        passport.use(new local_strategy({
                            passReqToCallback: true
                        }, (req, username, password, next) => {
                            if (!username) {
                                return next(new Error('[[error:invalid-email]]'));
                            }
                            if (!password) {
                                return next(new Error('[[error:invalid-password]]'));
                            }
                            nodebb_ldap.process(req, username, password, next);
                        }));
                    } catch (e) {
                        console.error('error with ldap auth, falling back to local login', e);
                        passport.use(local);
                    }
                }
            });
        },

        findLdapGroups: (callback) => {
            winston.verbose("[LDAP] findLdapGroups ")
            if (!master_config.groups_query) {
                return callback(null, []);
            }
            nodebb_ldap.adminClient((err, adminClient) => {
                //if (err) {
                //    return adminClient(null);
                //}
                var groups_search = {
                    filter: master_config.groups_query,
                    scope: 'sub',
                    attributes: ['cn', 'uniqueMember']
                };

                adminClient.search(master_config.base, groups_search, (err, res) => {
                    let groups = [];
                    if (err) {
                        return callback(new Error('groups could not be found'));
                    }
                    res.on('searchEntry', (entry) => {
                        groups.push(entry.object)
                    });

                    res.on('error', (resErr) => {
                        //assert.ifError(resErr);
                    });
                    res.on('end', () => {
                        adminClient.unbind();


                        callback(null, groups);
                    });
                });
            });
        },

        adminClient: (callback) => {
            const tlsOptions = {'rejectUnauthorized': false}
            const client = ldapjs.createClient({
                url: master_config.server + ':' + master_config.port,
                tlsOptions: tlsOptions,
                timeout: 2000
            });
            client.on('error', error => callback(error));

            client.bind(master_config.admin_user, master_config.password, (err) => {
                if (err) {
                    return callback(new Error('could not bind with admin config ' + err.message));
                }
                callback(null, client);
            });
        },

        createGroup: (ldapGroup, callback) => {
            const groupName = "ldap-" + ldapGroup.cn;
            const groupData = {
                name: groupName,
                userTitleEnabled: false,
                description: 'LDAP Group ' + ldapGroup.cn,
                hidden: 1,
                system: 1,
                private: 1,
                disableJoinRequests: true,
            };
            groups.create(groupData, () => {
                callback(null, groupName);
            });
        },

        process: (req, username, password, next) => {
            async.waterfall([
                    (next) => {
                        nodebb_ldap.adminClient((err, adminClient) => {
                            if (err) {
                                return next(err);
                            }
                            winston.verbose("[LDAP] uid=" + master_config.user_query.replace('%username%', username))
                            var opt = {
                                filter: master_config.user_query.replace('%username%', username),
                                sizeLimit: 1,
                                scope: 'sub',
                                attributes: ['dn', 'sAMAccountName', 'sn', 'mail', 'uid', //these fields are mandatory
                                    // optional fields. used to create the user id/fullname
                                    'givenName', 'displayName',
                                ]
                            };

                            adminClient.search(master_config.base, opt, (err, res) => {
                                var profile;
                                if (err) {
                                    return next(err);
                                }
                                res.on('searchEntry', (entry) => {
                                    profile = entry.object;
                                });
                                res.on('end', () => {
                                    adminClient.unbind();
                                    if (profile) {
                                        const tlsOptions = {'rejectUnauthorized': false}
                                        const userClient = ldapjs.createClient({
                                            url: master_config.server + ':' + master_config.port,
                                            tlsOptions: tlsOptions
                                        });
                                        userClient.bind(profile.dn, password, (err) => {
                                            userClient.unbind();
                                            if (err) {
                                                return next(new Error('[[error:invalid-email]]'));
                                            }

                                            nodebb_ldap.login(profile, (err, userObject) => {
                                                if (err) {
                                                    return next(new Error('[[error:invalid-email]]'));
                                                }
                                                return next(null, userObject);
                                            });
                                        });
                                    } else {
                                        return next(new Error('[[error:invalid-email]]'));
                                    }
                                });
                                res.on('error', (err) => {
                                    adminClient.unbind();
                                    return next(new Error('[[error:invalid-email]]'));
                                });

                            });
                        });
                    }
                ],
                (err, user) => {
                    if (err || !user) {
                        controllers.authentication.localLogin(req, username, password, next);
                    } else {
                        next(null, user);
                    }
                }
            );
        },

        login: (profile, callback) => {
            // build the username
            winston.verbose("[LDAP] Calling login")
            let fullname = profile.sn;
            if (profile[master_config.sname]) {
                fullname = profile[master_config.sname];
            }
            let username = fullname;
            if (profile[master_config.dname]) {
                username = profile[master_config.dname];
            }
            let email = profile.mail;
            if (profile[master_config.email_field]) {
                email = profile[master_config.email_field];
            }
            if (email.indexOf("@") === -1) {
                if (master_config.email_suffix.indexOf("@") === -1) {
                    email = email + "@" + master_config.email_suffix
                } else {
                    email = email + master_config.email_suffix
                }
            }
            winston.verbose("[LDAP] fullname: " + fullname)
            winston.verbose("[LDAP] username: " + username)
            winston.verbose("[LDAP] email: " + email)
            nodebb_ldap.getUserByLdapUid(profile.uid, (err, dbUser) => {
                if (err) {
                    return callback(err);
                }
                if (dbUser.uid !== 0) {
                    // user exists
                    // now we check the user groups
                    winston.verbose("[LDAP] user exists")
                    return nodebb_ldap.postLogin(dbUser.uid, profile.uid, callback);
                } else {
                    // New User
                    winston.verbose("[LDAP] user does not exists")
                    let pattern = new RegExp(/[\ ]*\(.*\)/);
                    if (pattern.test(username)) {
                        username = username.replace(pattern, '');
                    }
                    winston.verbose("[LDAP] username: " + username + " fullname: " + fullname + " email: " + email)
                    return user.create({username: username, fullname: fullname, email: email}, (err, uid) => {
                        if (err) {
                            return callback(err);
                        }
                        winston.verbose("[LDAP] Creating the user and set autovalidate to: " + master_config.autovalidate === "on")
                        if (master_config.autovalidate === "on") {
                            user.setUserField(uid, 'email:confirmed', 1);
                        }
                        user.setUserFields(uid, {
                            'nodebbldap:uid:': profile.uid
                        });
                        db.setObjectField('ldapid:uid', profile.uid, uid)
                        return nodebb_ldap.postLogin(uid, profile.uid, callback);
                    });
                }
            });
        },
        joinRegisteredGroup: (uid) => {
            winston.info("[GROUP] joinRegisteredGroup")
            const groupName = "registered";
            const groupData = {
                name: groupName,
                userTitleEnabled: false,
                description: 'Registered users Group',
                hidden: 1,
                system: 1,
                private: 1,
                disableJoinRequests: true,
            };
            winston.info("[GROUP] creating registered group")
            groups.create(groupData);
            winston.info("[GROUP] join registered group")
            return groups.join([groupName], uid);
        },
        postLogin: (uid, ldapId, callback) => {
            if (master_config.registeredGroup === "on") {
                nodebb_ldap.joinRegisteredGroup(uid);
            }
            async.waterfall([
                    nodebb_ldap.findLdapGroups,
                    (groups, callback) => {
                        winston.verbose("[LDAP] Groups " + groups)
                        async.each(groups,
                            (ldapGroup, callback) => {
                                winston.verbose("[LDAP] ldapGroup " + ldapGroup)
                                nodebb_ldap.groupJoin(ldapGroup, ldapId, uid, callback);
                            }, callback);
                    }],
                () => {
                    callback(null, {uid: uid});
                }
            );
        },

        groupJoin: (ldapGroup, ldapId, uid, callback) => {
            winston.verbose("[LDAP] groupJoin " + ldapGroup + " for user " + ldapId + " uid " + uid)
            nodebb_ldap.createGroup(ldapGroup,
                (err, groupId) => {
                    if (err) {
                        return callback(err);
                    }
                    let members = ldapGroup.uniqueMember;
                    if (!Array.isArray(members)) {
                        members = [members];
                    }
                    winston.verbose("[LDAP] groupJoin members " + members && typeof members)
                    let found = false
                    if (members) {

                        members.forEach(member => {
                            if (member && member.indexOf(ldapId) != -1) {
                                found = true
                            }
                        });
                    }
                    if (found) {
                        const groupsToJoin = [groupId];
                        if ((master_config.admin_groups || '').split(',').includes(ldapGroup.cn)) {
                            winston.verbose("[LDAP] joins admin group")
                            groupsToJoin.push('administrators');
                        }
                        if ((master_config.moderator_groups || '').split(',').includes(ldapGroup.cn)) {
                            groupsToJoin.push('Global Moderators');
                        }
                        return groups.join(groupsToJoin, uid, callback);
                    } else {
                        callback();
                    }
                }
            );
        },

        getUserByLdapUid: (ldapUid, callback) => {
            db.getObjectField('ldapid:uid', ldapUid, (err, uid) => {
                if (err) {
                    return callback(err);
                }
                // Fix the issue when ldapid is not existed yet
                if (!uid) {
                    return callback(null, {uid:0});
                }
                user.getUserData(uid, (err, data) => {
                    if (err) {
                        return callback(err);
                    }
                    callback(null, data);
                });
            });
        },
    };
    module.exports = nodebb_ldap;

}(module));
