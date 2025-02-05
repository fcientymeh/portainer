import { useState } from 'react';
import {
  Database,
  GitCommit,
  Hash,
  Server,
  Tag,
  Variable,
  Wrench,
} from 'lucide-react';
import clsx from 'clsx';

import { useSystemStatus } from '@/react/portainer/system/useSystemStatus';
import { useSystemVersion } from '@/react/portainer/system/useSystemVersion';
import { useIsEdgeAdmin } from '@/react/hooks/useUser';

import { Modal } from '@@/modals';
import { Button } from '@@/buttons';

import styles from './Footer.module.css';

export function BuildInfoModalButton() {
  const [isBuildInfoVisible, setIsBuildInfoVisible] = useState(false);
  const statusQuery = useSystemStatus();

  if (!statusQuery.data) {
    return null;
  }

  const { Version } = statusQuery.data;

  return (
    <>
      <button
        type="button"
        data-cy="portainerSidebar-versionNumber"
        className="btn-none"
        onClick={() => setIsBuildInfoVisible(true)}
      >
        {Version}
      </button>
      {isBuildInfoVisible && (
        <BuildInfoModal closeModal={() => setIsBuildInfoVisible(false)} />
      )}
    </>
  );
}

function BuildInfoModal({ closeModal }: { closeModal: () => void }) {
  const { isAdmin } = useIsEdgeAdmin({ noEnvScope: true });
  const versionQuery = useSystemVersion();
  const statusQuery = useSystemStatus();

  if (!statusQuery.data || !versionQuery.data) {
    return null;
  }

  const { Edition } = statusQuery.data;
  const { ServerVersion, DatabaseVersion, Build } = versionQuery.data;

  return (
    <Modal onDismiss={closeModal} aria-label="build-info-modal">
      <Modal.Header title={`Portainer ${Edition}`} />
      <Modal.Body>
        <div className={styles.versionInfo}>
          <table>
            <tbody>
              <tr>
                <td>
                  <span className="inline-flex items-center">
                    <Server size="13" className="space-right" />
                    Server Version: {ServerVersion}
                  </span>
                </td>
                <td>
                  <span className="inline-flex items-center">
                    <Database size="13" className="space-right" />
                    Database Version: {DatabaseVersion}
                  </span>
                </td>
              </tr>

            </tbody>
          </table>
        </div>
        <div className={styles.toolsList}>
          <span className="inline-flex items-center">
            <Wrench size="13" className="space-right" />
            Compilation tools:
          </span>

          <div className={styles.tools}>
            <span className="text-muted small">
              Nodejs v{Build.NodejsVersion}
            </span>
            <span className="text-muted small">Yarn v{Build.YarnVersion}</span>
            <span className="text-muted small">
              Webpack v{Build.WebpackVersion}
            </span>
            <span className="text-muted small">Go v{Build.GoVersion}</span>
          </div>

          </div>

          <div className={styles.tools}>
            <span className="text-muted small">
              AIP Portainer by AiSECLAB Sp. z o.o. <br/>
              based on Portainer CE under zlib {' '}
              < a href="https://github.com/portainer/portainer?tab=Zlib-1-ov-file#readme">license</a>
            </span>

         

        </div>




      </Modal.Body>
      <Modal.Footer>
        <Button
          className="w-full"
          onClick={closeModal}
          data-cy="portainerBuildInfoModal-CloseButton"
        >
          Ok
        </Button>
      </Modal.Footer>
    </Modal>
  );
}
