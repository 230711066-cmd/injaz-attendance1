import pg from 'pg';
import QRCode from 'qrcode';
import {randomBytes, pbkdf2 as pbkdf2Callback, timingSafeEqual, createHash} from 'node:crypto';
import {promisify} from 'node:util';
import {attendanceException} from '../../attendance-rules.mjs';
import supabaseCA from '../../supabase-ca.mjs';

const pbkdf2 = promisify(pbkdf2Callback);
const schema = process.env.INJAZ_SCHEMA || 'injaz';
if (!/^[a-z_][a-z0-9_]*$/.test(schema)) throw Error('Invalid database schema');
const pool = new pg.Pool({connectionString:process.env.DATABASE_URL, max:2, idleTimeoutMillis:10000, connectionTimeoutMillis:15000,
  ssl:process.env.INJAZ_TEST_SSL==='disable'?false:{rejectUnauthorized:true,ca:supabaseCA}, options:`-c search_path=${schema}`});
let initialized;
const digest = value => createHash('sha256').update(value).digest('hex');
const profile = row => ({id:Number(row.id),code:row.code,name:row.name,department:row.department,admin:row.admin});
class ApiError extends Error {constructor(message,status=400){super(message);this.status=status}}
async function hash(password,salt=randomBytes(16).toString('hex')) {
  return salt+':'+(await pbkdf2(password,salt,300000,32,'sha256')).toString('hex');
}
async function initialize(db){
  await db.query(`CREATE SCHEMA IF NOT EXISTS ${schema}; REVOKE ALL ON SCHEMA ${schema} FROM PUBLIC;
    CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY,code TEXT UNIQUE NOT NULL,name TEXT NOT NULL,department TEXT NOT NULL,password TEXT NOT NULL,admin INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires DOUBLE PRECISION NOT NULL);
    CREATE TABLE IF NOT EXISTS records(id BIGSERIAL PRIMARY KEY,user_id INTEGER NOT NULL,kind TEXT NOT NULL,timestamp TEXT NOT NULL);
    ALTER TABLE records ADD COLUMN IF NOT EXISTS note TEXT NOT NULL DEFAULT '';
    ALTER TABLE records ADD COLUMN IF NOT EXISTS exception_type TEXT NOT NULL DEFAULT '';
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS login_attempts(key TEXT PRIMARY KEY,attempts INTEGER NOT NULL,started DOUBLE PRECISION NOT NULL);
    CREATE INDEX IF NOT EXISTS records_user_last ON records(user_id,id);
    CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires);`);
}
const baseHeaders={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin'};
const json=(data,status=200,extra={})=>new Response(JSON.stringify(data),{status,headers:{...baseHeaders,'Content-Type':'application/json; charset=utf-8',...extra}});
const cookie=token=>`injaz_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${token?43200:0}`;

export default async function handler(request,context={}) {
  const path=new URL(request.url).pathname;
  if(path==='/api/health') return json({ok:true});
  if(!['GET','POST'].includes(request.method)) return json({error:'طلب غير مسموح.'},405);
  let body={};
  if(request.method==='POST'){
    if(request.headers.get('X-Injaz')!=='1'||request.headers.get('Content-Type')?.split(';')[0]!=='application/json')return json({error:'طلب غير مسموح.'},403);
    try{const text=await request.text();if(Buffer.byteLength(text)>16384)throw Error();body=JSON.parse(text);if(!body||typeof body!=='object'||Array.isArray(body))throw Error()}
    catch{return json({error:'راجع البيانات المدخلة.'},400)}
  }
  let db;
  try{
    db=await pool.connect();
    if(!initialized){initialized=initialize(db).catch(error=>{initialized=null;throw error});await initialized}else await initialized;
    await db.query('BEGIN');
    const result=await route(db,path,request,body,context);
    await db.query('COMMIT');
    return result;
  }catch(error){
    if(db)await db.query('ROLLBACK').catch(()=>{});
    if(error instanceof ApiError)return json({error:error.message},error.status);
    if(error.code==='23505')return json({error:'رقم الموظف مستخدم مسبقاً.'},409);
    console.error('INJAZ request failed:',error.code||error.name);
    return json({error:'تعذر حفظ العملية. حاول مرة أخرى أو راجع الإدارة.'},503);
  }finally{db?.release()}
}

async function route(db,path,request,body,context){
  const now=Date.now()/1000;
  const token=(request.headers.get('Cookie')||'').match(/(?:^|;\s*)injaz_session=([A-Za-z0-9_-]+)/)?.[1];
  const user=token?(await db.query('SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token=$1 AND s.expires>$2',[digest(token),now])).rows[0]:null;
  if(request.method==='GET'&&path==='/api/me')return json({user:user?profile(user):null,setup:!(await db.query('SELECT 1 FROM users LIMIT 1')).rowCount,local:false,setupTokenRequired:true});
  if(request.method==='POST'&&['/api/login','/api/setup'].includes(path)){
    const code=String(body.code||'').trim().toUpperCase(),password=String(body.password||'');
    if(!code||code.length>40||password.length>200)throw new ApiError('راجع رقم الموظف وكلمة المرور.');
    const key=digest(context.ip||'unknown-client');
    const attempt=(await db.query(`INSERT INTO login_attempts VALUES($1,1,$2::double precision) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN login_attempts.started<$2::double precision-300 THEN 1 ELSE login_attempts.attempts+1 END,started=CASE WHEN login_attempts.started<$2::double precision-300 THEN $2::double precision ELSE login_attempts.started END RETURNING attempts`,[key,now])).rows[0];
    if(attempt.attempts>10){await db.query('COMMIT');throw new ApiError('محاولات كثيرة. انتظر خمس دقائق.',429)}
    if(path==='/api/setup'){
      const expected=process.env.INJAZ_SETUP_TOKEN||'',provided=String(body.setupToken||'');
      if(!expected||digest(expected)!==digest(provided)) {await db.query('COMMIT');throw new ApiError('أدخل رمز إعداد الإدارة المحدد في إعدادات الاستضافة.',403)}
      await db.query('SELECT pg_advisory_xact_lock(89173216)');
      if((await db.query('SELECT 1 FROM users LIMIT 1')).rowCount)throw new ApiError('تم إعداد الإدارة مسبقاً.',409);
      if(password.length<10)throw new ApiError('كلمة المرور 10 أحرف على الأقل.');
      await db.query('INSERT INTO users(code,name,department,password,admin) VALUES($1,$2,$3,$4,1)',[code,'مدير إنجاز','الإدارة',await hash(password)]);
    }
    const account=(await db.query('SELECT * FROM users WHERE code=$1',[code])).rows[0];
    const stored=account?.password||await hash('dummy');
    const calculated=await hash(password,stored.split(':')[0]);
    if(!account||!timingSafeEqual(Buffer.from(stored),Buffer.from(calculated))){await db.query('COMMIT');throw new ApiError('رقم الموظف أو كلمة المرور غير صحيحة.',401)}
    await db.query('DELETE FROM login_attempts WHERE key=$1 OR started<$2::double precision-86400',[key,now]);
    await db.query('DELETE FROM sessions WHERE expires<$1',[now]);
    const session=randomBytes(32).toString('base64url');
    await db.query('INSERT INTO sessions VALUES($1,$2,$3)',[digest(session),account.id,now+43200]);
    return json({user:profile(account)},200,{'Set-Cookie':cookie(session)});
  }
  if(!user)throw new ApiError('سجل الدخول أولاً.',403);
  if(request.method==='GET'&&path==='/api/records'){
    const sql='SELECT r.*,u.name,u.code,u.department FROM records r JOIN users u ON u.id=r.user_id';
    return json((await db.query(sql+(user.admin?'':' WHERE r.user_id=$1')+' ORDER BY r.id DESC',user.admin?[]:[user.id])).rows);
  }
  if(request.method==='POST'&&path==='/api/logout'){
    await db.query('DELETE FROM sessions WHERE user_id=$1',[user.id]);return json({ok:true},200,{'Set-Cookie':cookie('')});
  }
  if(request.method==='POST'&&path==='/api/attendance'){
    const kind=body.kind;if(!['in','out'].includes(kind))throw new ApiError('راجع نوع الحركة.');
    await db.query('SELECT pg_advisory_xact_lock(89173216)');
    const last=(await db.query('SELECT kind FROM records WHERE user_id=$1 ORDER BY id DESC LIMIT 1',[user.id])).rows[0];
    if(last?.kind===kind||(!last&&kind==='out'))throw new ApiError(last?'الحركة مسجلة مسبقاً؛ اختر الحركة التالية.':'سجل حضورك أولاً.',409);
    const timestamp=new Date(Date.now()+3*3600000).toISOString().slice(0,19)+'+03:00';
    const note=typeof body.note==='string'?body.note.trim():'';
    if(note.length>1000)throw new ApiError('الملاحظة يجب ألا تتجاوز 1000 حرف.');
    const exception=attendanceException(kind,new Date(timestamp));
    if(exception&&!note)throw new ApiError(exception==='late'?'اكتب سبب التأخير عن الساعة 9 صباحاً.':'اكتب سبب الانصراف المبكر قبل الساعة 5 عصراً.');
    await db.query('INSERT INTO records(user_id,kind,timestamp,note,exception_type) VALUES($1,$2,$3,$4,$5)',[user.id,kind,timestamp,note,exception]);return json({ok:true});
  }
  if(!user.admin)throw new ApiError('هذه العملية للإدارة فقط.',403);
  if(request.method==='GET'&&path==='/api/users')return json((await db.query('SELECT id,code,name,department,admin FROM users ORDER BY id')).rows.map(profile));
  if(request.method==='GET'&&path==='/api/settings')return json({url:(await db.query("SELECT value FROM settings WHERE key='url'")).rows[0]?.value||''});
  if(request.method==='GET'&&path==='/api/qr'){
    const url=(await db.query("SELECT value FROM settings WHERE key='url'")).rows[0]?.value;
    if(!url)throw new ApiError('احفظ رابط النظام أولاً.');
    return new Response(await QRCode.toString(url+'/attendance',{type:'svg',margin:4}),{headers:{...baseHeaders,'Content-Type':'image/svg+xml'}});
  }
  if(request.method==='POST'&&path==='/api/users'){
    const values=['code','name','department','password'].map(k=>String(body[k]||'').trim());
    if(values.some(v=>!v||v.length>200)||values[0].length>40||values[3].length<10)throw new ApiError('أكمل البيانات وكلمة مرور من 10 أحرف على الأقل.');
    values[0]=values[0].toUpperCase();values[3]=await hash(values[3]);
    await db.query('INSERT INTO users(code,name,department,password) VALUES($1,$2,$3,$4)',values);return json({ok:true});
  }
  if(request.method==='POST'&&path==='/api/settings'){
    const url=String(body.url||'').replace(/\/+$/,'');let u;try{u=new URL(url)}catch{throw new ApiError('أدخل رابط HTTPS الصحيح.')}
    if(u.protocol!=='https:'||u.username||u.password||u.pathname!=='/'||u.search||u.hash||url.length>500)throw new ApiError('أدخل رابط HTTPS بدون مسار إضافي.');
    await db.query("INSERT INTO settings VALUES('url',$1) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",[url]);return json({ok:true});
  }
  if(request.method==='POST'&&path==='/api/password'){
    const password=String(body.password||''),id=Number(body.id);
    if(password.length<10||password.length>200||!Number.isSafeInteger(id))throw new ApiError('راجع كلمة المرور.');
    await db.query('UPDATE users SET password=$1 WHERE id=$2',[await hash(password),id]);await db.query('DELETE FROM sessions WHERE user_id=$1',[id]);return json({ok:true});
  }
  throw new ApiError('الصفحة غير موجودة.',404);
}

export const config={path:'/api/*'};
export const closePool=()=>pool.end();
