import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import {randomBytes} from 'node:crypto';
import supabaseCA from './supabase-ca.mjs';

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
    assert.equal((await call('attendance',{kind:'in'},employeeCookie)).status,200);
    assert.equal((await call('attendance',{kind:'in'},employeeCookie)).status,409);
    assert.equal((await call('attendance',{kind:'out'},employeeCookie)).status,200);
    assert.equal((await (await call('records',null,employeeCookie)).json()).length,2);
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
