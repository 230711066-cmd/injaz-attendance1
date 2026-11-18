import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import {randomBytes} from 'node:crypto';
import supabaseCA from './supabase-ca.mjs';
import {attendanceException} from './attendance-rules.mjs';

test('Baghdad shift boundaries use 09:00 and 17:00',()=>{
  for(const [time,kind,expected] of [
    ['08:59:59','in',''],['09:00:00','in',''],['09:00:01','in','late'],
    ['16:59:59','out','early'],['17:00:00','out',''],['17:00:01','out',''],
    ['23:30:00','in','late'],['00:30:00','out','early']
  ]) assert.equal(attendanceException(kind,new Date('2026-11-18T'+time+'+03:00')),expected);
});

test('Netlify API: private accounts, attendance, persistence and QR',{skip:!process.env.INJAZ_TEST_DATABASE_URL},async()=>{
  const schema='injaz_test_'+randomBytes(5).toString('hex');
  process.env.DATABASE_URL=process.env.INJAZ_TEST_DATABASE_URL;
  process.env.INJAZ_SCHEMA=schema;
  process.env.INJAZ_SETUP_TOKEN='test-only-setup-token';
  const {default:handler,closePool}=await import('./netlify/functions/api.mjs');
  let adminCookie='',employeeCookie='';
  const call=(path,body,cookie='')=>handler(new Request('https://attendance.test/api/'+path,{method:body?'POST':'GET',headers:{...(body?{'Content-Type':'application/json','X-Injaz':'1'}:{}),Cookie:cookie},body:body?JSON.stringify(body):undefined}),{ip:'integration-test'});
  try{
    assert.equal((await call('records')).status,403);
    assert.equal((await call('setup',{code:'ADMIN',password:'Strong-password-123',setupToken:'wrong'})).status,403);
    let response=await call('setup',{code:'ADMIN',password:'Strong-password-123',setupToken:process.env.INJAZ_SETUP_TOKEN});
    assert.equal(response.status,200,await response.clone().text());adminCookie=response.headers.get('set-cookie').split(';')[0];
    assert.match(response.headers.get('set-cookie'),/Secure/);
    assert.equal((await call('users',{code:'E1',name:'موظف الاختبار',department:'صيانة',password:'Staff-secret-123'},adminCookie)).status,200);
    response=await call('login',{code:'E1',password:'Staff-secret-123'});assert.equal(response.status,200);employeeCookie=response.headers.get('set-cookie').split(';')[0];
    assert.equal((await call('users',null,employeeCookie)).status,403);
    assert.equal((await call('attendance',{kind:'out'},employeeCookie)).status,409);
    if(attendanceException('in'))assert.equal((await call('attendance',{kind:'in',note:'   '},employeeCookie)).status,400);
    assert.equal((await call('attendance',{kind:'in',note:'Transport delay <test>'},employeeCookie)).status,200);
    assert.equal((await call('attendance',{kind:'in'},employeeCookie)).status,409);
    if(attendanceException('out'))assert.equal((await call('attendance',{kind:'out'},employeeCookie)).status,400);
    assert.equal((await call('attendance',{kind:'out',note:'Medical appointment'},employeeCookie)).status,200);
    const saved=await (await call('records',null,employeeCookie)).json();
    assert.equal(saved.length,2);
    assert.equal(saved[0].note,'Medical appointment');
    assert.equal(saved[1].note,'Transport delay <test>');
    assert.equal(saved[0].exception_type,attendanceException('out',new Date(saved[0].timestamp)));
    assert.equal(saved[1].exception_type,attendanceException('in',new Date(saved[1].timestamp)));
    assert.equal((await call('settings',{url:'https://attendance.test'},adminCookie)).status,200);
    response=await call('qr',null,adminCookie);assert.equal(response.status,200);assert.match(await response.text(),/<svg/);
    const employee=(await (await call('users',null,adminCookie)).json()).find(u=>u.code==='E1');
    assert.equal((await call('password',{id:employee.id,password:'Changed-secret-123'},adminCookie)).status,200);
    assert.equal((await call('records',null,employeeCookie)).status,403);
    assert.equal((await call('logout',{},adminCookie)).status,200);
    assert.equal((await call('records',null,adminCookie)).status,403);
  }finally{
    await closePool();
    const cleanup=new pg.Client({connectionString:process.env.DATABASE_URL,ssl:process.env.INJAZ_TEST_SSL==='disable'?false:{rejectUnauthorized:true,ca:supabaseCA}});
    await cleanup.connect();
    assert.match(schema,/^injaz_test_[a-f0-9]{10}$/);
    await cleanup.query(`DROP SCHEMA ${schema} CASCADE`);await cleanup.end();
  }
});
