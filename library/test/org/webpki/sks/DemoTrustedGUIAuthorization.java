/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.sks;

import javax.swing.JComponent;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;

import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;

import org.webpki.sks.AppUsage;
import org.webpki.sks.Grouping;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.SKSException;

public class DemoTrustedGUIAuthorization extends DummyTrustedGUIAuthorization {
    @Override
    public byte[] getTrustedAuthorization(PassphraseFormat format,
                                          Grouping grouping,
                                          AppUsage appUsage,
                                          String friendlyName) throws SKSException {
        byte[] authorization = null;
        JPasswordField pwd = new JPasswordField(10);
        pwd.addAncestorListener(new AncestorListener() {
            @Override
            public void ancestorAdded(AncestorEvent e) {
                JComponent component = e.getComponent();
                component.requestFocusInWindow();
            }

            @Override
            public void ancestorMoved(AncestorEvent e) {
            }

            @Override
            public void ancestorRemoved(AncestorEvent e) {
            }
        });

        int action = JOptionPane.showConfirmDialog(null,
                pwd,
                "Enter PIN",
                JOptionPane.OK_CANCEL_OPTION);
        if (action == JOptionPane.OK_OPTION) {
            authorization = convertToUTF8(format, new String(pwd.getPassword()));
        }
        return authorization;
    }

    @Override
    public String getImplementation() {
        return "Primitive (non-secure) GUI version";
    }
}
