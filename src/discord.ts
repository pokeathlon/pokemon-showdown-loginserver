import { readFileSync } from 'node:fs';
import * as crypto from 'node:crypto';

import { Config } from './config-loader.ts';
import { ActionError, type ActionContext } from './server.ts';
import * as tables from './tables.ts';
import { Session } from './user.ts';
import { escapeHTML, time, toID } from './utils.ts';

export type DiscordUser = {
	id: string,
	username: string,
	global_name: string | null,
};

type TicketValues = { username?: string, assertion?: string, ticket?: string, suggestion?: string };

export const Discord = new class {
	readonly authorizeURL = 'https://discord.com/oauth2/authorize';
	readonly tokenURL = 'https://discord.com/api/oauth2/token';
	readonly userURL = 'https://discord.com/api/users/@me';
	readonly ticketTime = 10 * 60;
	readonly codeChars = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
	readonly loginCodes = new Map<string, { userid: string, time: number }>();
	codeAttempts = { time: 0, count: 0 };

	readonly callbackPage = readFileSync(
		import.meta.dirname + "/public/discord-callback.html",
		'utf-8'
	);

	getConfig() {
		const config = Config.discord;
		if (!config?.clientid || !config.clientsecret || !config.redirecturi) {
			throw new ActionError("Discord login is not configured on this server.", 500);
		}
		return config;
	}

	sign(data: string) {
		return crypto.createHmac('sha256', Config.privatekey).update(data).digest('hex');
	}

	seal(payload: { [k: string]: string }) {
		const data = Buffer.from(JSON.stringify({ ...payload, time: time() })).toString('base64url');
		return `${data}.${this.sign(data)}`;
	}

	unseal(sealed?: string): { [k: string]: string } {
		const [data, signature] = (sealed || '').split('.');
		if (!data || !signature) throw new ActionError("Your Discord login expired. Please try again.");
		const expected = Buffer.from(this.sign(data));
		const given = Buffer.from(signature);
		let payload;
		try {
			if (expected.length === given.length && crypto.timingSafeEqual(expected, given)) {
				payload = JSON.parse(Buffer.from(data, 'base64url').toString());
			}
		} catch {}
		if (!payload) {
			throw new ActionError("Your Discord login could not be verified. Please try again.");
		}
		if (time() - Number(payload.time) > this.ticketTime) {
			throw new ActionError("Your Discord login expired. Please try again.");
		}
		return payload;
	}

	makeLoginCode(userid: string) {
		let code = '';
		for (let i = 0; i < 8; i++) code += this.codeChars[crypto.randomInt(this.codeChars.length)];
		this.loginCodes.set(code, { userid, time: time() });
		return `${code.slice(0, 4)}-${code.slice(4)}`;
	}

	useLoginCode(code: string) {
		if (time() - this.codeAttempts.time > 60) this.codeAttempts = { time: time(), count: 0 };
		if (++this.codeAttempts.count > 30) {
			throw new ActionError("Too many login code attempts. Please try again in a minute.");
		}
		code = code.toUpperCase().replace(/[^0-9A-Z]/g, '');
		const login = this.loginCodes.get(code);
		this.loginCodes.delete(code);
		if (!login || time() - login.time > this.ticketTime) {
			throw new ActionError("That login code is invalid or expired.");
		}
		return login.userid;
	}

	getAuthorizeURL(challstr: string, serverid: string) {
		const config = this.getConfig();
		const url = new URL(this.authorizeURL);
		url.searchParams.set('client_id', config.clientid);
		url.searchParams.set('redirect_uri', config.redirecturi);
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('scope', config.guildid ? 'identify guilds.members.read' : 'identify');
		url.searchParams.set('state', this.seal({ challstr, serverid }));
		return url.toString();
	}

	fetchAPI(url: string, accessToken: string) {
		return fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
	}

	async exchangeCode(code: string) {
		const config = this.getConfig();
		const response = await fetch(this.tokenURL, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				client_id: config.clientid,
				client_secret: config.clientsecret,
				grant_type: 'authorization_code',
				code,
				redirect_uri: config.redirecturi,
			}),
		});
		const data = response.ok ? await response.json() as { access_token?: string } : null;
		if (!data?.access_token) {
			throw new ActionError("Discord rejected this login. Please try again.");
		}
		return data.access_token;
	}

	async fetchUser(accessToken: string): Promise<DiscordUser> {
		const response = await this.fetchAPI(this.userURL, accessToken);
		const data = response.ok ? await response.json() as Partial<DiscordUser> : null;
		if (!data?.id || !data.username) {
			throw new ActionError("Could not read your Discord account. Please try again.");
		}
		return { id: data.id, username: data.username, global_name: data.global_name || null };
	}

	async requireGuildMember(accessToken: string) {
		const { guildid } = this.getConfig();
		if (!guildid) return;
		const url = `${this.userURL}/guilds/${encodeURIComponent(guildid)}/member`;
		if (!(await this.fetchAPI(url, accessToken)).ok) {
			throw new ActionError("You must be a member of this server's Discord to log in.");
		}
	}

	suggestName(user: DiscordUser) {
		for (const candidate of [user.username, user.global_name]) {
			const userid = toID(candidate).slice(0, 18);
			if (/[a-z]/.test(userid) && !userid.startsWith('guest') && Session.isUseridAllowed(userid)) {
				return userid;
			}
		}
		return '';
	}

	validateName(username: string) {
		const userid = toID(username);
		if (!userid) throw new ActionError(`You must specify a username.`);
		if (!/[a-z]/.test(userid)) throw new ActionError(`Your username must include at least one letter.`);
		if (userid.startsWith('guest')) throw new ActionError(`Your username cannot start with 'guest'.`);
		if (userid.length > 18) throw new ActionError(`Your username must be less than 19 characters long.`);
		if (!Session.isUseridAllowed(userid)) throw new ActionError(`Your username contains disallowed text.`);
		return userid;
	}

	async getLinkedUser(discordid: string): Promise<{ username: string } | null> {
		const link = await tables.discordLinks.selectOne()`WHERE discordid = ${discordid} ORDER BY time`;
		if (!link) return null;
		const user = await tables.users.get(link.userid);
		if (user) return user;
		await tables.discordLinks.delete(link.userid);
		return this.getLinkedUser(discordid);
	}

	async link(discordid: string, username: string, ip: string) {
		const userid = this.validateName(username);
		if (await tables.discordLinks.selectOne()`WHERE discordid = ${discordid}`) {
			throw new ActionError(`This Discord account is already linked to an account.`);
		}
		const user = await tables.users.insertIgnore({
			userid, username, passwordhash: null, email: null, registertime: time(), ip,
		});
		if (!user.affectedRows) {
			throw new ActionError(`Your username is already taken.`);
		}
		await tables.discordLinks.set(userid, { discordid, time: time() });
		return userid;
	}

	async addName(linkedid: string, username: string, ip: string) {
		const link = await tables.discordLinks.get(linkedid);
		if (!link) return false;
		const userid = this.validateName(username);
		const user = await tables.users.insertIgnore({
			userid, username, passwordhash: null, email: null, registertime: time(), ip,
		});
		if (!user.affectedRows) return false;
		await tables.discordLinks.set(userid, { discordid: link.discordid, time: time() });
		return true;
	}

	async logIn(context: ActionContext, username: string, challstr: string) {
		await context.session.createSession(username);
		await context.session.setSid();
		return context.session.getAssertion(toID(username), Config.challengekeyid, null, challstr);
	}

	renderCallbackPage(values: TicketValues) {
		return this.callbackPage.replace(
			/\{\{(\w+)\}\}/g, (match, key: keyof TicketValues) => escapeHTML(values[key] || '')
		);
	}
};
