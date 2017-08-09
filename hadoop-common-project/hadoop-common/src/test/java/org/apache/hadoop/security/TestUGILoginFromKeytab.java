/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.security;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.minikdc.MiniKdc;
import org.apache.hadoop.security.UserGroupInformation.AuthenticationMethod;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.security.PrivilegedExceptionAction;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.kerberos.KeyTab;
import javax.security.auth.login.LoginContext;

/**
 * Verify UGI login from keytab. Check that the UGI is
 * configured to use keytab to catch regressions like
 * HADOOP-10786.
 */
public class TestUGILoginFromKeytab {

  private MiniKdc kdc;
  private File workDir;
  private ExecutorService executor;

  @Rule
  public final TemporaryFolder folder = new TemporaryFolder();

  @Before
  public void startMiniKdc() throws Exception {
    // This setting below is required. If not enabled, UGI will abort
    // any attempt to loginUserFromKeytab.
    Configuration conf = new Configuration();
    conf.set(CommonConfigurationKeys.HADOOP_SECURITY_AUTHENTICATION,
        "kerberos");
    UserGroupInformation.setConfiguration(conf);
    UserGroupInformation.setShouldRenewImmediatelyForTests(true);
    workDir = folder.getRoot();
    kdc = new MiniKdc(MiniKdc.createConf(), workDir);
    kdc.start();
    executor = Executors.newCachedThreadPool();
  }

  @After
  public void stopMiniKdc() {
    if (kdc != null) {
      kdc.stop();
    }
    if (executor != null) {
      executor.shutdownNow();
    }
  }

  /**
   * Login from keytab using the MiniKDC and verify the UGI can successfully
   * relogin from keytab as well. This will catch regressions like HADOOP-10786.
   */
  @Test
  public void testUGILoginFromKeytab() throws Exception {
    String principal = "foo";
    File keytab = new File(workDir, "foo.keytab");
    kdc.createPrincipal(keytab, principal);

    UserGroupInformation.loginUserFromKeytab(principal, keytab.getPath());
    UserGroupInformation ugi = UserGroupInformation.getLoginUser();
    Assert.assertTrue("UGI should be configured to login from keytab",
        ugi.isFromKeytab());

    // Verify relogin from keytab.
    User user = ugi.getSubject().getPrincipals(User.class).iterator().next();
    final long firstLogin = user.getLastLogin();
    ugi.reloginFromKeytab();
    final long secondLogin = user.getLastLogin();
    Assert.assertTrue("User should have been able to relogin from keytab",
        secondLogin > firstLogin);
  }

  // verify ugi is keytab based and optional whether a keytab is present
  // in subject.
  private static KeyTab checkIsKeytab(UserGroupInformation ugi,
      boolean required) {
    Assert.assertTrue(ugi.isFromKeytab());
    Set<KeyTab> keytabs =
        ugi.getSubject().getPrivateCredentials(KeyTab.class);
    KeyTab keytab = keytabs.isEmpty() ? null : keytabs.iterator().next();
    Assert.assertEquals(ugi.getSubject().toString(), required, keytab != null);
    return keytab;
  }

  private static KerberosTicket getTicket(UserGroupInformation ugi) {
    Set<KerberosTicket> tickets =
        ugi.getSubject().getPrivateCredentials(KerberosTicket.class);
    return tickets.isEmpty() ? null : tickets.iterator().next();
  }

  // verify ugi has expected principal, a keytab, and has a ticket for
  // the expected principal.
  private static KerberosTicket checkTicketAndKeytab(UserGroupInformation ugi,
      KerberosPrincipal principal) {
    Assert.assertEquals(principal.getName(), ugi.getUserName());
    checkIsKeytab(ugi, true);
    KerberosTicket ticket = getTicket(ugi);
    Assert.assertNotNull(ticket);
    Assert.assertEquals(principal, ticket.getClient());
    return ticket;
  }

  @Test
  public void testReloginForUGIFromSubject() throws Exception {
    final KerberosPrincipal principal1 = new KerberosPrincipal("user1");
    final File keytab1 = new File(workDir, "user1.keytab");
    kdc.createPrincipal(keytab1, "user1");

    UserGroupInformation.loginUserFromKeytab(
        principal1.getName(), keytab1.getPath());

    final KerberosPrincipal principal2 = new KerberosPrincipal("user2");
    final File keytab2 = new File(workDir, "user2.keytab");
    kdc.createPrincipal(keytab2, "user2");

    // Login from a pre-set subject with a keytab
    final Subject subject = new Subject();
    KeyTab keytab = KeyTab.getInstance(keytab2);
    subject.getPrivateCredentials().add(keytab);
    subject.getPrincipals().add(principal2);

    UserGroupInformation.loginUserFromKeytab(
        principal1.getName(), keytab1.getPath());
    final UserGroupInformation loginUser = UserGroupInformation.getLoginUser();

    loginUser.doAs(new PrivilegedExceptionAction<Void>() {
      @Override
      public Void run() throws IOException {
        KerberosTicket loginTicket =
            checkTicketAndKeytab(loginUser, principal1);

        UserGroupInformation subjectUser =
            UserGroupInformation.getUGIFromSubject(subject);
        KerberosTicket ticket = checkTicketAndKeytab(subjectUser, principal2);

        // verify login user got a new ticket.
        loginUser.reloginFromKeytab();
        KerberosTicket newLoginTicket =
            checkTicketAndKeytab(loginUser, principal1);
        Assert.assertNotEquals(loginTicket.getAuthTime(),
            newLoginTicket.getAuthTime());

        // verify subject user got a new ticket.
        subjectUser.reloginFromKeytab();
        Assert.assertNotEquals(ticket.getAuthTime(),
            checkTicketAndKeytab(subjectUser, principal2).getAuthTime());

        // verify subject ugi relogin did not affect the login user.
        Assert.assertEquals(newLoginTicket.getAuthTime(),
            checkTicketAndKeytab(loginUser, principal1).getAuthTime());

        return null;
      }
    });
  }

  @Test
  public void testReloginForLoginFromSubject() throws Exception {
    final KerberosPrincipal principal1 = new KerberosPrincipal("user1");
    final File keytab1 = new File(workDir, "user1.keytab");
    kdc.createPrincipal(keytab1, "user1");

    final KerberosPrincipal principal2 = new KerberosPrincipal("user2");
    final File keytab2 = new File(workDir, "user2.keytab");
    kdc.createPrincipal(keytab2, "user2");

    // login principal1 with a keytab.
    UserGroupInformation.loginUserFromKeytab(
        principal1.getName(), keytab1.getPath());
    final UserGroupInformation originalLoginUser =
        UserGroupInformation.getLoginUser();

    originalLoginUser.doAs(new PrivilegedExceptionAction<Void>() {
      @Override
      public Void run() throws IOException {
        KerberosTicket originalLoginUserTicket =
            checkTicketAndKeytab(originalLoginUser, principal1);

        // login principal2 from a subject with keytab.
        final Subject subject = new Subject();
        KeyTab keytab = KeyTab.getInstance(keytab2);
        subject.getPrivateCredentials().add(keytab);
        subject.getPrincipals().add(principal2);
        UserGroupInformation.loginUserFromSubject(subject);

        // verify the new login user has expected principal and keytab.
        UserGroupInformation newLoginUser =
            UserGroupInformation.getLoginUser();
        KerberosTicket newLoginUserTicket =
            checkTicketAndKeytab(newLoginUser, principal2);

        // verify new login user gets a new ticket, original login user
        // not affected.
        newLoginUser.reloginFromKeytab();
        KerberosTicket newLoginUserTicket2 =
            checkTicketAndKeytab(newLoginUser, principal2);
        Assert.assertNotEquals(
            newLoginUserTicket.getAuthTime(),
            newLoginUserTicket2.getAuthTime());
        Assert.assertEquals(
            originalLoginUserTicket.getAuthTime(),
            checkTicketAndKeytab(originalLoginUser, principal1).getAuthTime());

        // verify original login user gets a new ticket, new login user
        // not affected.
        originalLoginUser.reloginFromKeytab();
        Assert.assertNotEquals(originalLoginUserTicket.getAuthTime(),
            checkTicketAndKeytab(originalLoginUser, principal1).getAuthTime());
        Assert.assertEquals(
            newLoginUserTicket2.getAuthTime(),
            checkTicketAndKeytab(newLoginUser, principal2).getAuthTime());
        return null;
      }
    });
  }

  @Test
  public void testReloginAfterFailedRelogin() throws Exception {
    KerberosPrincipal principal = new KerberosPrincipal("user1");
    File keytab = new File(workDir, "user1.keytab");
    File keytab2 = new File(keytab + ".backup");
    kdc.createPrincipal(keytab, "user1");

    UserGroupInformation.loginUserFromKeytab(
        principal.getName(), keytab.getPath());
    final UserGroupInformation loginUser = UserGroupInformation.getLoginUser();
    checkTicketAndKeytab(loginUser, principal);

    // move the keytab to induce a relogin failure.
    Assert.assertTrue(keytab.renameTo(keytab2));
    try {
      loginUser.reloginFromKeytab();
      Assert.fail("relogin should fail");
    } catch (KerberosAuthException kae) {
      // expected.
    }

    // even though no KeyTab object, ugi should know it's keytab based.
    checkIsKeytab(loginUser, false);
    Assert.assertNull(getTicket(loginUser));

    // move keytab back to enable relogin to succeed.
    Assert.assertTrue(keytab2.renameTo(keytab));
    loginUser.reloginFromKeytab();
    checkTicketAndKeytab(loginUser, principal);
  }

  // verify getting concurrent relogins blocks to avoid indeterminate
  // credentials corruption, but getting a ugi for the subject does not block.
  @Test(timeout=180000)
  public void testConcurrentRelogin() throws Exception {
    final CyclicBarrier barrier = new CyclicBarrier(2);
    final CountDownLatch latch = new CountDownLatch(1);
    assertTrue(UserGroupInformation.isSecurityEnabled());

    final KerberosPrincipal principal = new KerberosPrincipal("testUser");
    final File keytab = new File(workDir, "user1.keytab");
    kdc.createPrincipal(keytab, "testUser");

    // fake up a keytab based ugi.
    final Subject subject = new Subject();
    subject.getPrincipals().add(principal);
    subject.getPrivateCredentials().add(KeyTab.getInstance(keytab));
    UserGroupInformation.loginUserFromSubject(subject);
    final UserGroupInformation loginUgi =
        UserGroupInformation.getLoginUser();
    assertEquals(AuthenticationMethod.KERBEROS,
        loginUgi.getAuthenticationMethod());
    assertTrue(loginUgi.isFromKeytab());

    // create a new ugi instance based on subject from the logged in user.
    final UserGroupInformation clonedUgi =
        UserGroupInformation.getUGIFromSubject(loginUgi.getSubject());
    assertEquals(AuthenticationMethod.KERBEROS,
        clonedUgi.getAuthenticationMethod());
    assertTrue(clonedUgi.isFromKeytab());

    // cause first relogin to block on a barrier in what is expected to
    // be an atomic relogin.
    User user = getUser(loginUgi);
    final LoginContext spyLogin = Mockito.spy(user.getLogin());
    user.setLogin(spyLogin);
    Mockito.doAnswer(new Answer<Void>(){
      @Override
      public Void answer(InvocationOnMock invocation)
          throws Throwable {
        latch.countDown();
        barrier.await();
        invocation.callRealMethod();
        return null;
      }
    }).when(spyLogin).login();

    Future<Void> relogin = executor.submit(
        new Callable<Void>(){
          @Override
          public Void call() throws Exception {
            Thread.currentThread().setName("relogin");
            loginUgi.reloginFromKeytab();
            return null;
          }
        });
    // wait for the thread to block on the barrier in login.
    latch.await();

    // although the logout removed the keytab instance, verify the ugi
    // knows from its login params that it is supposed to be from a keytab.
    assertTrue(clonedUgi.isFromKeytab());

    // another concurrent re-login should block.
    Mockito.doNothing().when(spyLogin).logout();
    Mockito.doNothing().when(spyLogin).login();
    Future<UserGroupInformation> clonedRelogin = executor.submit(
        new Callable<UserGroupInformation>(){
          @Override
          public UserGroupInformation call() throws Exception {
            Thread.currentThread().setName("clonedRelogin");
            clonedUgi.checkTGTAndReloginFromKeytab();
            return clonedUgi;
          }
        });

    try {
      clonedRelogin.get(2, TimeUnit.SECONDS);
      fail("relogin didn't block!");
    } catch (TimeoutException te) {
      // expected
    }

    // concurrent UGI instantiation should not block and again should
    // know it's supposed to be from a keytab.
    loginUgi.doAs(new PrivilegedExceptionAction<Void>(){
      @Override
      public Void run() throws Exception {
        UserGroupInformation ugi = UserGroupInformation.getCurrentUser();
        assertEquals(principal.getName(), ugi.getUserName());
        assertTrue(ugi.isFromKeytab());
        return null;
      }
    });
    clonedUgi.doAs(new PrivilegedExceptionAction<Void>(){
      @Override
      public Void run() throws Exception {
        UserGroupInformation ugi = UserGroupInformation.getCurrentUser();
        assertEquals(principal.getName(), ugi.getUserName());
        assertTrue(ugi.isFromKeytab());
        return null;
      }
    });

    // second relogin should still be blocked until the original relogin
    // is blocked.
    assertFalse(clonedRelogin.isDone());
    barrier.await();
    relogin.get();
    clonedRelogin.get();
  }

  private User getUser(UserGroupInformation ugi) {
    final Subject subject = ugi.getSubject();
    Iterator<User> iter = subject.getPrincipals(User.class).iterator();
    return iter.hasNext() ? iter.next() : null;
  }
}
