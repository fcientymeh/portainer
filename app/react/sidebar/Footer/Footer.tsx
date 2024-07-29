import { PropsWithChildren } from 'react';
import clsx from 'clsx';

import { isBE } from '@/react/portainer/feature-flags/feature-flags.service';

import { UpdateNotification } from './UpdateNotifications';
import { BuildInfoModalButton } from './BuildInfoModal';
import '@reach/dialog/styles.css';
import styles from './Footer.module.css';
import Logo from './portainer_logo.svg?c';
const logo2 = require('./logo2.png');

export function Footer() {
  return isBE ? <BEFooter /> : <CEFooter />;
}

function CEFooter() {
  return (
    <div className={clsx(styles.root, 'text-center')}>
      <UpdateNotification />

      <FooterContent>
        <img alt='logo2' style={{ width: 100 }} src={String(logo2)} />
      </FooterContent> <BuildInfoModalButton />
    </div>
  );
}

function BEFooter() {
  return (
    <div className={clsx(styles.root, 'text-center')}>
      <FooterContent>
        <span>&copy;</span>
        <span>Portainer Business Edition</span>

        <BuildInfoModalButton />
      </FooterContent>
    </div>
  );
}

function FooterContent({ children }: PropsWithChildren<unknown>) {
  return (
    <div className="mx-auto flex items-center justify-center space-x-1 text-[10px] text-gray-2 be:text-white-10">
      {children}
    </div>
  );
}
