import { useEffect, useState } from 'react';
import { StyleSheet, Text, TouchableOpacity, View, ScrollView } from 'react-native';
import SecureNetwork from './specs/NativeSecureNetwork';

export default function App() {
  const [responseLog, setResponseLog] = useState('');
  const [jwtToken, setJwtToken] = useState(null);
  const [isProvisioned, setIsProvisioned] = useState(false);
  const baseURL = 'https://192.168.0.179:8443'

  const provisionIdentity = async () => {
    try {
      const result = await SecureNetwork.provisionIdentity();
      setIsProvisioned(true);
      setResponseLog(`✅ PROVISIONED: ${result}`);
    } catch (error) {
      setResponseLog(`❌ PROVISION FAILED:\n${error?.message || error}`);
    }
  };

  useEffect(() => {
    provisionIdentity();
  }, []);

  const triggerPinnedRequest = async () => {
    if (!isProvisioned) {
      setResponseLog('❌ ERROR: Tap "0. Provision mTLS" first!');
      return;
    }

    setResponseLog('Initiating mTLS request...');
    try {
      const body = JSON.stringify({
        username: "Allen",
        password: "Password1*"
      });

      const responseString = await SecureNetwork.postWithMTLS(
        `${baseURL}/api/v1/login`,
        body,
        {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      );

      const data = JSON.parse(responseString);
      if (data.token) {
        setJwtToken(data.token);
      }
      setResponseLog(`✅ LOGIN SUCCESS:\n${JSON.stringify(data, null, 2)}`);

    } catch (error) {
      setResponseLog(`❌ LOGIN FAILED:\n${error?.message || error}`);
    }
  };

  const fetchCertInfo = async () => {
    if (!isProvisioned) {
      setResponseLog('ERROR: Tap "0. Provision mTLS" first!');
      return;
    }

    setResponseLog('Fetching Server Certificate Info...');
    try {
      const responseString = await SecureNetwork.getWithMTLS(
        `${baseURL}/api/v1/cert-info`,
        {
          'Authorization': `Bearer ${jwtToken}`,
          'Accept': 'application/json'
        }
      );

      const data = JSON.parse(responseString);
      setResponseLog(`CERT INFO:\n${JSON.stringify(data, null, 2)}`);

    } catch (error) {
      setResponseLog(`CERT INFO FAILED:\n${error?.message || error}`);
    }
  };

  const fetchSecureData = async () => {
    if (!isProvisioned) {
      setResponseLog('ERROR: Tap "0. Provision mTLS" first!');
      return;
    }
    if (!jwtToken) {
      setResponseLog('ERROR: Please login first to get a JWT token!');
      return;
    }

    setResponseLog('Fetching secure data with JWT...');
    try {
      const responseString = await SecureNetwork.getWithMTLS(
        `${baseURL}/api/v1/data`,
        {
          'Authorization': `Bearer ${jwtToken}`,
          'Accept': 'application/json'
        }
      );

      const data = JSON.parse(responseString);
      setResponseLog(`DATA SUCCESS:\n${JSON.stringify(data, null, 2)}`);

    } catch (error) {
      setResponseLog(`DATA FAILED:\n${error?.message || error}`);
    }
  };

  const triggerOtherRequest = async () => {
    setResponseLog('Initiating standard fetch request...');
    try {
      const response = await fetch('https://jsonplaceholder.typicode.com/todos', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: "Hello Charles!" })
      });
      const data = await response.json();
      setResponseLog(`NORMAL SUCCESS:\n${JSON.stringify(data, null, 2)}`);
    } catch (error) {
      setResponseLog(`NORMAL FAILED:\n${error.message}`);
    }
  };

  return (
    <View style={styles.container}>
      <ScrollView contentContainerStyle={styles.scrollButtons} style={styles.buttonContainer}>
        <TouchableOpacity
          style={[styles.button, { backgroundColor: isProvisioned ? 'green' : 'orange' }]}
          onPress={provisionIdentity}>
          <Text style={styles.buttonText}>0. mTLS Provisioned</Text>
        </TouchableOpacity>
        <TouchableOpacity style={[styles.button, { backgroundColor: 'red' }]} onPress={triggerPinnedRequest}>
          <Text style={styles.buttonText}>1. Test mTLS Secure Login</Text>
        </TouchableOpacity>
        <TouchableOpacity style={[styles.button, { backgroundColor: 'yellow' }]} onPress={fetchSecureData}>
          <Text style={styles.buttonText}>2. Fetch JWT Data</Text>
        </TouchableOpacity>
        <TouchableOpacity style={[styles.button, { backgroundColor: 'grey' }]} onPress={fetchCertInfo}>
          <Text style={styles.buttonText}>3. Fetch Cert Info</Text>
        </TouchableOpacity>
        <TouchableOpacity style={[styles.button, { backgroundColor: 'pink' }]} onPress={triggerOtherRequest}>
          <Text style={styles.buttonText}>Dummy Other Req</Text>
        </TouchableOpacity>
      </ScrollView>
      <View style={styles.logContainer}>
        <ScrollView>
          <Text style={styles.logText}>{responseLog}</Text>
        </ScrollView>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    paddingTop: 100,
  },
  buttonContainer: {
    width: '90%',
    maxHeight: '30%',
  },
  scrollButtons: {
    paddingBottom: 10,
  },
  button: {
    padding: 15,
    borderRadius: 10,
    marginBottom: 10,
    alignItems: 'center',
  },
  buttonText: {
    fontWeight: 'bold',
  },
  logContainer: {
    width: '90%',
    flex: 1,
    backgroundColor: 'black',
    borderRadius: 10,
    padding: 15,
    marginBottom: 40,
    marginTop: 10,
  },
  logText: {
    color: 'cyan',
  }
});