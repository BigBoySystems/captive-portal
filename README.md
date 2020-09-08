captive-portal
==============

A captive portal service for the thingy

Quick Start
-----------

### Prerequisites

 *  pipenv

### Development

Install all the dependencies:

```
pipenv install --dev
```

Run the dev server:

```
INTERFACE=wlan0 pipenv run dev
```

**WARNING:** the development server does not gracefully exit the app. This
leads to processes not killed and interface not shut down on exit.

Use this command instead:

```
pipenv run prod --host localhost --port 8000 --debug wlan0
```

Or if you need a Unix socket (for the backend):

```
pipenv run prod --unix /run/captive-portal.sock --debug wlan0
```
