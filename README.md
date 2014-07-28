This is a rewrite of the happstack-authenticate library. The original
version was too clever in all the wrong areas making things like
resetting your lost password impossible.

This version aims to be easier to use and less clever. There are also
some new features being hoped for:

 1. more modular authentication support. Previously, all
 authentication methods had to be built in. It would be nice if it was
 possible to select which authentication are available at build time
 by installing additional packages.

 2. ability to restriction user account creation. Some sites allow
 users to sign themselves up, but not all do.

We should review this document and make sure we are implementing everything accordingly.

http://stackoverflow.com/questions/549/the-definitive-guide-to-forms-based-website-authentication/477578#477578

When authenticating we generally have some process by which the user
confirms their identity -- and then some other method by which we
recognize that user in later requests. For example, they might submit
a username and password to prove their identity. In later requests
they merely submit an authentication token. Some will argue that the
use of the authentication token pushes us into the realm of 'sessions'
and is also therefore not RESTful.